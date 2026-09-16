package scenario

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	"teleport-auth-stress/internal/config"
	"teleport-auth-stress/internal/identity"
)

// LocalLoginTOTP is the "local-login-totp" scenario: the same full proxy
// web login as local-login-webauthn, but solving the challenge with a
// TOTP code instead of a WebAuthn assertion. Secondary per
// instructions.md domain constraint #1: a TOTP code cannot be replayed
// and lives in a ~30s window, so this scenario is only as fast as
// (seeded TOTP users / 30s) — WebAuthn has no such ceiling and is the
// primary login scenario. See docs/methodology.md's M7 notes for the
// operator-facing implication (seed enough users, or expect this
// scenario's real achievable rate to plateau well below what the ramp
// requests).
type LocalLoginTOTP struct {
	httpClient *http.Client
	baseURL    string
	users      []identity.UserFixture
	pool       *identity.KeyPool
	next       atomic.Uint64
}

func (s *LocalLoginTOTP) Name() string { return "local-login-totp" }

// Setup mirrors LocalLoginWebAuthn.Setup exactly, filtering for
// fixtures.secondFactor: totp users instead of webauthn ones.
func (s *LocalLoginTOTP) Setup(ctx context.Context, env *Env) error {
	if env.Fixtures == nil {
		return fmt.Errorf("local-login-totp Setup requires env.Fixtures (run authseed apply first)")
	}

	users := make([]identity.UserFixture, 0, len(env.Fixtures.Users))
	for _, u := range env.Fixtures.Users {
		if u.SecondFactor == config.SecondFactorTOTP {
			users = append(users, u)
		}
	}
	if len(users) == 0 {
		return fmt.Errorf("no totp users in fixture state; check fixtures.secondFactor and re-run authseed apply")
	}

	pool, err := env.Fixtures.KeyPool()
	if err != nil {
		return fmt.Errorf("loading key pool: %w", err)
	}
	if pool.Size() == 0 {
		return fmt.Errorf("key pool is empty")
	}

	s.users = users
	s.pool = pool
	s.baseURL = "https://" + env.Config.Target.ProxyAddr
	s.httpClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: env.Config.Target.InsecureSkipVerify}, //nolint:gosec // opt-in via config, for disposable test clusters only
		},
	}
	return nil
}

// Execute performs one full login: begin (network) -> compute the
// current TOTP code locally from the user's already-registered soft
// device (no network, no keygen — domain constraint #4) -> finish
// (network, returns certs directly).
func (s *LocalLoginTOTP) Execute(ctx context.Context) (Result, error) {
	idx := s.next.Add(1) - 1
	user := s.users[idx%uint64(len(s.users))]
	kp := s.pool.At(int(idx))

	device, err := user.TOTPDevice()
	if err != nil {
		return Result{Outcome: ClientError}, fmt.Errorf("reconstructing totp device for %s: %w", user.Username, err)
	}

	var phases []Phase

	beginStart := time.Now()
	var beginResp loginBeginResponse
	err = postJSON(ctx, s.httpClient, s.baseURL+"/webapi/mfa/login/begin", loginBeginRequest{
		User: user.Username,
		Pass: user.Password,
	}, &beginResp)
	phases = append(phases, Phase{Name: "mfa-begin", Duration: time.Since(beginStart).Nanoseconds()})
	if err != nil {
		return Result{Phases: phases, Outcome: ClassifyError(err)}, err
	}
	if !beginResp.TOTPChallenge {
		err := fmt.Errorf("server did not offer a totp challenge for %s (cluster second-factor settings?)", user.Username)
		return Result{Phases: phases, Outcome: ClientError}, err
	}

	solveStart := time.Now()
	code, err := device.Code(time.Now())
	phases = append(phases, Phase{Name: "mfa-solve", Duration: time.Since(solveStart).Nanoseconds()})
	if err != nil {
		return Result{Phases: phases, Outcome: ClientError}, fmt.Errorf("generating totp code: %w", err)
	}

	finishStart := time.Now()
	var finishResp sshLoginResponse
	err = postJSON(ctx, s.httpClient, s.baseURL+"/webapi/mfa/login/finish", loginFinishRequest{
		User:      user.Username,
		Password:  user.Password,
		TOTPCode:  code,
		SSHPubKey: kp.SSHPublicKey,
		TLSPubKey: kp.TLSPublicKey,
		TTL:       loginCertTTL,
	}, &finishResp)
	phases = append(phases, Phase{Name: "mfa-finish", Duration: time.Since(finishStart).Nanoseconds()})
	if err != nil {
		return Result{Phases: phases, Outcome: ClassifyError(err)}, err
	}

	return Result{
		Phases:  phases,
		Outcome: Success,
		Bytes:   int64(len(finishResp.Cert) + len(finishResp.TLSCert)),
	}, nil
}

func (s *LocalLoginTOTP) Teardown(ctx context.Context) error { return nil }
