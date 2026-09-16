package scenario

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gravitational/trace"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	authproto "github.com/gravitational/teleport/api/client/proto"

	"teleport-auth-stress/internal/config"
	"teleport-auth-stress/internal/identity"
)

func newTestTOTPFixture(t *testing.T, username, password string) identity.UserFixture {
	t.Helper()
	device, err := identity.NewSoftTOTPDeviceFromChallenge(&authproto.TOTPRegisterChallenge{
		Secret:        "JBSWY3DPEHPK3PXP",
		Algorithm:     "SHA1",
		PeriodSeconds: 30,
		Digits:        6,
	})
	if err != nil {
		t.Fatalf("NewSoftTOTPDeviceFromChallenge: %v", err)
	}
	return identity.UserFixture{
		Username:     username,
		Password:     password,
		SecondFactor: config.SecondFactorTOTP,
		TOTPSecret:   device.Secret,
	}
}

// newFakeTOTPProxy builds an httptest server implementing just enough of
// /webapi/mfa/login/{begin,finish} to exercise LocalLoginTOTP.Execute
// against, verifying the submitted code with the real pquerna/otp
// library (the same one the soft device itself uses to generate it, but
// this is an independent verification path, not a round-trip of the
// same code) — mirrors locallogin_test.go's real-library verification
// for WebAuthn.
func newFakeTOTPProxy(t *testing.T, fixtures map[string]identity.UserFixture, beginOverride, finishOverride func(w http.ResponseWriter) bool) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()

	mux.HandleFunc("/webapi/mfa/login/begin", func(w http.ResponseWriter, r *http.Request) {
		if beginOverride != nil && beginOverride(w) {
			return
		}
		var req loginBeginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			trace.WriteError(w, trace.BadParameter("bad request body"))
			return
		}
		fx, ok := fixtures[req.User]
		if !ok || fx.Password != req.Pass {
			trace.WriteError(w, trace.AccessDenied("invalid credentials"))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(loginBeginResponse{TOTPChallenge: true}) //nolint:errcheck
	})

	mux.HandleFunc("/webapi/mfa/login/finish", func(w http.ResponseWriter, r *http.Request) {
		if finishOverride != nil && finishOverride(w) {
			return
		}
		var req loginFinishRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			trace.WriteError(w, trace.BadParameter("bad request body"))
			return
		}
		fx, ok := fixtures[req.User]
		if !ok || fx.Password != req.Password {
			trace.WriteError(w, trace.AccessDenied("invalid credentials"))
			return
		}
		valid, err := totp.ValidateCustom(req.TOTPCode, fx.TOTPSecret, time.Now(), totp.ValidateOpts{
			Period: 30, Digits: 6, Algorithm: otp.AlgorithmSHA1,
		})
		if err != nil || !valid {
			trace.WriteError(w, trace.AccessDenied("invalid totp code"))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sshLoginResponse{ //nolint:errcheck
			Username: req.User,
			Cert:     []byte("fake-ssh-cert"),
			TLSCert:  []byte("fake-tls-cert"),
		})
	})

	return httptest.NewServer(mux)
}

func newTOTPScenarioAgainst(t *testing.T, srv *httptest.Server, users []identity.UserFixture) *LocalLoginTOTP {
	t.Helper()
	pool, err := identity.GenerateKeyPool(config.KeyAlgorithmEd25519, 4)
	if err != nil {
		t.Fatalf("GenerateKeyPool: %v", err)
	}
	return &LocalLoginTOTP{
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		users:      users,
		pool:       pool,
	}
}

func TestLocalLoginTOTP_Name(t *testing.T) {
	s := &LocalLoginTOTP{}
	if s.Name() != "local-login-totp" {
		t.Errorf("Name() = %q, want local-login-totp", s.Name())
	}
}

func TestLocalLoginTOTP_SuccessfulLogin_PhaseTimingsAndBytes(t *testing.T) {
	fx := newTestTOTPFixture(t, "stress-00000", "s3cret-password")
	srv := newFakeTOTPProxy(t, map[string]identity.UserFixture{fx.Username: fx}, nil, nil)
	defer srv.Close()

	s := newTOTPScenarioAgainst(t, srv, []identity.UserFixture{fx})

	execStart := time.Now()
	result, err := s.Execute(context.Background())
	totalElapsed := time.Since(execStart)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Outcome != Success {
		t.Fatalf("Outcome = %v, want Success", result.Outcome)
	}
	wantPhases := []string{"mfa-begin", "mfa-solve", "mfa-finish"}
	if len(result.Phases) != len(wantPhases) {
		t.Fatalf("got %d phases, want %d (%v); phases=%+v", len(result.Phases), len(wantPhases), wantPhases, result.Phases)
	}
	for i, name := range wantPhases {
		if result.Phases[i].Name != name {
			t.Errorf("phase[%d].Name = %q, want %q", i, result.Phases[i].Name, name)
		}
	}

	var sum time.Duration
	for _, p := range result.Phases {
		sum += time.Duration(p.Duration)
	}
	if sum == 0 || totalElapsed == 0 {
		t.Fatalf("sum=%v totalElapsed=%v, want both > 0", sum, totalElapsed)
	}
	ratio := float64(sum) / float64(totalElapsed)
	if ratio < 0.95 || ratio > 1.05 {
		t.Errorf("phase sum %v is %.1f%% of total elapsed %v, want within 5%%", sum, ratio*100, totalElapsed)
	}
}

func TestLocalLoginTOTP_InvalidPassword_ClassifiesAsClientError(t *testing.T) {
	fx := newTestTOTPFixture(t, "stress-00002", "correct-password")
	srv := newFakeTOTPProxy(t, map[string]identity.UserFixture{fx.Username: fx}, nil, nil)
	defer srv.Close()

	badUser := fx
	badUser.Password = "wrong-password"
	s := newTOTPScenarioAgainst(t, srv, []identity.UserFixture{badUser})

	result, err := s.Execute(context.Background())
	if err == nil {
		t.Fatal("expected an error for wrong password")
	}
	if result.Outcome != ClientError {
		t.Errorf("Outcome = %v, want ClientError", result.Outcome)
	}
}

func TestLocalLoginTOTP_Lockout(t *testing.T) {
	fx := newTestTOTPFixture(t, "stress-00003", "pw")
	srv := newFakeTOTPProxy(t, map[string]identity.UserFixture{fx.Username: fx},
		func(w http.ResponseWriter) bool {
			trace.WriteError(w, trace.AccessDenied("%s", lockoutMessage))
			return true
		}, nil)
	defer srv.Close()

	s := newTOTPScenarioAgainst(t, srv, []identity.UserFixture{fx})
	result, _ := s.Execute(context.Background())
	if result.Outcome != Lockout {
		t.Errorf("Outcome = %v, want Lockout", result.Outcome)
	}
}

func TestLocalLoginTOTP_RateLimited(t *testing.T) {
	fx := newTestTOTPFixture(t, "stress-00004", "pw")
	srv := newFakeTOTPProxy(t, map[string]identity.UserFixture{fx.Username: fx},
		func(w http.ResponseWriter) bool {
			trace.WriteError(w, trace.LimitExceeded("slow down"))
			return true
		}, nil)
	defer srv.Close()

	s := newTOTPScenarioAgainst(t, srv, []identity.UserFixture{fx})
	result, _ := s.Execute(context.Background())
	if result.Outcome != RateLimited {
		t.Errorf("Outcome = %v, want RateLimited", result.Outcome)
	}
}

// TestLocalLoginTOTP_NoHotPathKeygen is the same direct-counter proof
// M3's WebAuthn scenario uses, applied here: no keypair generation
// occurs inside Execute (domain constraint #4).
func TestLocalLoginTOTP_NoHotPathKeygen(t *testing.T) {
	fx := newTestTOTPFixture(t, "stress-00006", "pw")
	srv := newFakeTOTPProxy(t, map[string]identity.UserFixture{fx.Username: fx}, nil, nil)
	defer srv.Close()

	s := newTOTPScenarioAgainst(t, srv, []identity.UserFixture{fx})

	identity.ResetKeyGenCount()
	const n = 10
	for i := 0; i < n; i++ {
		if _, err := s.Execute(context.Background()); err != nil {
			t.Fatalf("Execute[%d]: %v", i, err)
		}
	}
	if got := identity.KeyGenCount(); got != 0 {
		t.Errorf("KeyGenCount() after %d Execute calls = %d, want 0", n, got)
	}
}

func TestLocalLoginTOTP_Setup_RequiresFixtures(t *testing.T) {
	s := &LocalLoginTOTP{}
	if err := s.Setup(context.Background(), &Env{}); err == nil {
		t.Fatal("expected error when env.Fixtures is nil")
	}
}

func TestLocalLoginTOTP_Setup_RequiresTOTPUsers(t *testing.T) {
	s := &LocalLoginTOTP{}
	err := s.Setup(context.Background(), &Env{Fixtures: &identity.FixtureState{
		Users: []identity.UserFixture{{Username: "u", SecondFactor: config.SecondFactorWebAuthn}},
	}})
	if err == nil {
		t.Fatal("expected error when no seeded user has secondFactor=totp")
	}
}
