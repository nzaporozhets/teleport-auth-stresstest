package scenario

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/gravitational/trace"

	webauthnpb "github.com/gravitational/teleport/api/types/webauthn"

	"teleport-auth-stress/internal/config"
	"teleport-auth-stress/internal/identity"
)

const (
	testRPID      = "example.com"
	testOrigin    = "https://example.com"
	testChallenge = "0123456789abcdef0123456789abcdef"
)

// testWebAuthnFixture bundles a UserFixture with the underlying soft
// device and its real, library-verified COSE public key, so the fake
// server below can cryptographically verify Execute's assertion the
// same way a real Teleport auth server would (via go-webauthn), not
// just check the JSON shape.
type testWebAuthnFixture struct {
	user                identity.UserFixture
	credentialPublicKey []byte
}

func newTestWebAuthnFixture(t *testing.T, username, password string) testWebAuthnFixture {
	t.Helper()

	device, err := identity.NewSoftWebAuthnDevice()
	if err != nil {
		t.Fatalf("NewSoftWebAuthnDevice: %v", err)
	}

	// Register once against a synthetic challenge, purely so we can
	// extract a real, go-webauthn-verified COSE public key for the fake
	// server to check assertions against below — mirrors M1's own
	// registration test (webauthn_soft_test.go), not re-testing it.
	regChallenge := make([]byte, 32)
	if _, err := rand.Read(regChallenge); err != nil {
		t.Fatalf("rand: %v", err)
	}
	regResp, err := device.SignRegistration(testOrigin, &webauthnpb.CredentialCreation{
		PublicKey: &webauthnpb.PublicKeyCredentialCreationOptions{
			Challenge: regChallenge,
			Rp:        &webauthnpb.RelyingPartyEntity{Id: testRPID, Name: "Test RP"},
		},
	})
	if err != nil {
		t.Fatalf("SignRegistration: %v", err)
	}
	regBody, err := json.Marshal(map[string]any{
		"id":    encodeBase64URL(regResp.RawId),
		"rawId": encodeBase64URL(regResp.RawId),
		"type":  regResp.Type,
		"response": map[string]any{
			"clientDataJSON":    encodeBase64URL(regResp.Response.ClientDataJson),
			"attestationObject": encodeBase64URL(regResp.Response.AttestationObject),
		},
	})
	if err != nil {
		t.Fatalf("marshalling registration body: %v", err)
	}
	pcc, err := protocol.ParseCredentialCreationResponseBytes(regBody)
	if err != nil {
		t.Fatalf("ParseCredentialCreationResponseBytes: %v", err)
	}
	if _, err := pcc.Verify(
		encodeBase64URL(regChallenge), false, testRPID,
		[]string{testOrigin}, nil, protocol.TopOriginIgnoreVerificationMode, nil,
	); err != nil {
		t.Fatalf("registration did not verify: %v", err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(device.Key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	return testWebAuthnFixture{
		user: identity.UserFixture{
			Username:              username,
			Password:              password,
			SecondFactor:          config.SecondFactorWebAuthn,
			WebAuthnCredentialID:  device.CredentialID,
			WebAuthnPrivateKeyPEM: keyPEM,
		},
		credentialPublicKey: pcc.Response.AttestationObject.AuthData.AttData.CredentialPublicKey,
	}
}

// newFakeProxy builds an httptest server implementing just enough of
// /webapi/mfa/login/{begin,finish} to exercise LocalLoginWebAuthn.Execute
// against, including real cryptographic verification of the WebAuthn
// assertion via go-webauthn (the same library the real server uses).
func newFakeProxy(t *testing.T, fixtures map[string]testWebAuthnFixture, beginOverride, finishOverride func(w http.ResponseWriter) bool) *httptest.Server {
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
		if !ok || fx.user.Password != req.Pass {
			trace.WriteError(w, trace.AccessDenied("invalid credentials"))
			return
		}
		resp := loginBeginResponse{
			WebauthnChallenge: &credentialAssertion{
				Response: publicKeyCredentialRequestOptions{
					Challenge:      []byte(testChallenge),
					RelyingPartyID: testRPID,
				},
			},
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp) //nolint:errcheck
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
		if !ok || fx.user.Password != req.Password {
			trace.WriteError(w, trace.AccessDenied("invalid credentials"))
			return
		}
		if req.WebauthnChallengeResponse == nil {
			trace.WriteError(w, trace.BadParameter("missing webauthn challenge response"))
			return
		}

		assertionBody, err := json.Marshal(req.WebauthnChallengeResponse)
		if err != nil {
			trace.WriteError(w, trace.BadParameter("bad assertion encoding"))
			return
		}
		pca, err := protocol.ParseCredentialRequestResponseBytes(assertionBody)
		if err != nil {
			trace.WriteError(w, trace.AccessDenied("parsing assertion: %v", err))
			return
		}
		if err := pca.Verify(
			encodeBase64URL([]byte(testChallenge)), testRPID,
			[]string{testOrigin}, nil, protocol.TopOriginIgnoreVerificationMode,
			"", false, fx.credentialPublicKey,
		); err != nil {
			trace.WriteError(w, trace.AccessDenied("invalid webauthn assertion: %v", err))
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sshLoginResponse{ //nolint:errcheck
			Username: req.User,
			Cert:     []byte("fake-ssh-cert"),
			TLSCert:  []byte("fake-tls-cert"),
			HostSigners: []trustedCerts{
				{ClusterName: "test", TLSCertificates: [][]byte{[]byte("fake-ca-cert")}},
			},
		})
	})

	return httptest.NewServer(mux)
}

func newScenarioAgainst(t *testing.T, srv *httptest.Server, users []identity.UserFixture) *LocalLoginWebAuthn {
	t.Helper()
	pool, err := identity.GenerateKeyPool(config.KeyAlgorithmEd25519, 4)
	if err != nil {
		t.Fatalf("GenerateKeyPool: %v", err)
	}
	return &LocalLoginWebAuthn{
		httpClient: srv.Client(),
		baseURL:    srv.URL,
		origin:     testOrigin,
		users:      users,
		pool:       pool,
	}
}

func TestLocalLoginWebAuthn_Name(t *testing.T) {
	s := &LocalLoginWebAuthn{}
	if s.Name() != "local-login-webauthn" {
		t.Errorf("Name() = %q, want local-login-webauthn", s.Name())
	}
}

func TestLocalLoginWebAuthn_SuccessfulLogin_PhaseTimingsAndBytes(t *testing.T) {
	fx := newTestWebAuthnFixture(t, "stress-00000", "s3cret-password")
	srv := newFakeProxy(t, map[string]testWebAuthnFixture{fx.user.Username: fx}, nil, nil)
	defer srv.Close()

	s := newScenarioAgainst(t, srv, []identity.UserFixture{fx.user})

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
	if result.Bytes != int64(len("fake-ssh-cert")+len("fake-tls-cert")) {
		t.Errorf("Bytes = %d, want %d", result.Bytes, len("fake-ssh-cert")+len("fake-tls-cert"))
	}

	// M3 acceptance criterion: phase timings sum to the total round trip
	// within 5%.
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

func TestLocalLoginWebAuthn_InvalidPassword_ClassifiesAsClientError(t *testing.T) {
	fx := newTestWebAuthnFixture(t, "stress-00002", "correct-password")
	srv := newFakeProxy(t, map[string]testWebAuthnFixture{fx.user.Username: fx}, nil, nil)
	defer srv.Close()

	badUser := fx.user
	badUser.Password = "wrong-password"
	s := newScenarioAgainst(t, srv, []identity.UserFixture{badUser})

	result, err := s.Execute(context.Background())
	if err == nil {
		t.Fatal("expected an error for wrong password")
	}
	if result.Outcome != ClientError {
		t.Errorf("Outcome = %v, want ClientError", result.Outcome)
	}
	if len(result.Phases) != 1 || result.Phases[0].Name != "mfa-begin" {
		t.Errorf("expected exactly one mfa-begin phase on begin failure, got %+v", result.Phases)
	}
}

func TestLocalLoginWebAuthn_Lockout(t *testing.T) {
	fx := newTestWebAuthnFixture(t, "stress-00003", "pw")
	srv := newFakeProxy(t, map[string]testWebAuthnFixture{fx.user.Username: fx},
		func(w http.ResponseWriter) bool {
			trace.WriteError(w, trace.AccessDenied("%s", lockoutMessage))
			return true
		}, nil)
	defer srv.Close()

	s := newScenarioAgainst(t, srv, []identity.UserFixture{fx.user})
	result, _ := s.Execute(context.Background())
	if result.Outcome != Lockout {
		t.Errorf("Outcome = %v, want Lockout", result.Outcome)
	}
}

func TestLocalLoginWebAuthn_RateLimited(t *testing.T) {
	fx := newTestWebAuthnFixture(t, "stress-00004", "pw")
	srv := newFakeProxy(t, map[string]testWebAuthnFixture{fx.user.Username: fx},
		func(w http.ResponseWriter) bool {
			trace.WriteError(w, trace.LimitExceeded("slow down"))
			return true
		}, nil)
	defer srv.Close()

	s := newScenarioAgainst(t, srv, []identity.UserFixture{fx.user})
	result, _ := s.Execute(context.Background())
	if result.Outcome != RateLimited {
		t.Errorf("Outcome = %v, want RateLimited", result.Outcome)
	}
}

func TestLocalLoginWebAuthn_ServerScaledToZero(t *testing.T) {
	fx := newTestWebAuthnFixture(t, "stress-00005", "pw")
	srv := newFakeProxy(t, map[string]testWebAuthnFixture{fx.user.Username: fx}, nil, nil)
	users := []identity.UserFixture{fx.user}
	s := newScenarioAgainst(t, srv, users)
	srv.Close() // simulate the target having gone away entirely

	result, err := s.Execute(context.Background())
	if err == nil {
		t.Fatal("expected an error when the server is unreachable")
	}
	if result.Outcome != ServerError {
		t.Errorf("Outcome = %v, want ServerError (connection refused must not be counted as latency)", result.Outcome)
	}
}

// TestLocalLoginWebAuthn_NoHotPathKeygen is the M3 acceptance proof: no
// keypair generation occurs inside Execute. It uses the direct counter
// in internal/identity rather than an allocation-based proxy, so it's
// unambiguous rather than statistical.
func TestLocalLoginWebAuthn_NoHotPathKeygen(t *testing.T) {
	fx := newTestWebAuthnFixture(t, "stress-00006", "pw")
	srv := newFakeProxy(t, map[string]testWebAuthnFixture{fx.user.Username: fx}, nil, nil)
	defer srv.Close()

	s := newScenarioAgainst(t, srv, []identity.UserFixture{fx.user})

	identity.ResetKeyGenCount()
	const n = 50
	for i := 0; i < n; i++ {
		if _, err := s.Execute(context.Background()); err != nil {
			t.Fatalf("Execute[%d]: %v", i, err)
		}
	}
	if got := identity.KeyGenCount(); got != 0 {
		t.Errorf("KeyGenCount() after %d Execute calls = %d, want 0 (keys must be drawn from the pre-generated pool, never generated inline)", n, got)
	}
}

func TestLocalLoginWebAuthn_Setup_RequiresFixtures(t *testing.T) {
	s := &LocalLoginWebAuthn{}
	if err := s.Setup(context.Background(), &Env{}); err == nil {
		t.Fatal("expected error when env.Fixtures is nil")
	}
}

func TestLocalLoginWebAuthn_Setup_RequiresWebAuthnUsers(t *testing.T) {
	s := &LocalLoginWebAuthn{}
	err := s.Setup(context.Background(), &Env{Fixtures: &identity.FixtureState{
		Users: []identity.UserFixture{{Username: "u", SecondFactor: config.SecondFactorTOTP}},
	}})
	if err == nil {
		t.Fatal("expected error when no seeded user has secondFactor=webauthn")
	}
}

func TestLocalLoginWebAuthn_Setup_RequiresNonEmptyKeyPool(t *testing.T) {
	s := &LocalLoginWebAuthn{}
	err := s.Setup(context.Background(), &Env{
		Config: &config.Config{Target: config.Target{ProxyAddr: "example.com:443"}},
		Fixtures: &identity.FixtureState{
			Users:        []identity.UserFixture{{Username: "u", SecondFactor: config.SecondFactorWebAuthn}},
			KeyPoolState: identity.KeyPoolFixture{Algorithm: config.KeyAlgorithmEd25519},
		},
	})
	if err == nil {
		t.Fatal("expected error when the key pool is empty")
	}
}
