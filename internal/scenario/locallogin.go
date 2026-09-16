package scenario

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"sync/atomic"
	"time"

	webauthnpb "github.com/gravitational/teleport/api/types/webauthn"

	"teleport-auth-stress/internal/config"
	"teleport-auth-stress/internal/identity"
)

// loginCertTTL is the certificate validity requested on a successful
// login. This scenario only measures the login round-trip; it discards
// the returned certificate rather than keeping a connection open (unlike
// cert-renewal, a login scenario's whole point is to repeat the login
// itself, not to reuse its result).
const loginCertTTL = 30 * time.Minute

// LocalLoginWebAuthn is the "local-login-webauthn" scenario: a full
// proxy web login (password + WebAuthn) producing user certs. This is
// the headline scenario per instructions.md — WebAuthn has no replay
// window, unlike TOTP (domain constraint #1), so it's the primary login
// scenario and local-login-totp is secondary.
type LocalLoginWebAuthn struct {
	httpClient *http.Client
	baseURL    string
	origin     string
	users      []identity.UserFixture
	pool       *identity.KeyPool
	next       atomic.Uint64
}

func (s *LocalLoginWebAuthn) Name() string { return "local-login-webauthn" }

// Setup loads seeded WebAuthn users and the keypair pool from fixture
// state. Unlike cert-renewal, this scenario needs no admin-assisted
// bootstrap — every seeded user already has a password and a registered
// WebAuthn device (authseed apply, M1); Execute performs the entire
// login itself every time, so there's nothing to pre-issue.
func (s *LocalLoginWebAuthn) Setup(ctx context.Context, env *Env) error {
	if env.Fixtures == nil {
		return fmt.Errorf("local-login-webauthn Setup requires env.Fixtures (run authseed apply first)")
	}

	users := make([]identity.UserFixture, 0, len(env.Fixtures.Users))
	for _, u := range env.Fixtures.Users {
		if u.SecondFactor == config.SecondFactorWebAuthn {
			users = append(users, u)
		}
	}
	if len(users) == 0 {
		return fmt.Errorf("no webauthn users in fixture state; check fixtures.secondFactor and re-run authseed apply")
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
	s.origin = identity.OriginFromProxyAddr(env.Config.Target.ProxyAddr)
	s.httpClient = &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: env.Config.Target.InsecureSkipVerify}, //nolint:gosec // opt-in via config, for disposable test clusters only
		},
	}
	return nil
}

// Execute performs one full login: begin (network) -> solve the
// WebAuthn challenge locally with the user's already-registered soft
// device (no network, no keygen — the device's key was created once
// during authseed apply and the request's SSH/TLS public keys are drawn
// from the pre-generated pool, domain constraint #4) -> finish (network,
// returns certs directly, no further round-trip).
func (s *LocalLoginWebAuthn) Execute(ctx context.Context) (Result, error) {
	idx := s.next.Add(1) - 1
	user := s.users[idx%uint64(len(s.users))]
	kp := s.pool.At(int(idx))

	device, err := user.WebAuthnDevice()
	if err != nil {
		return Result{Outcome: ClientError}, fmt.Errorf("reconstructing webauthn device for %s: %w", user.Username, err)
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
	if beginResp.WebauthnChallenge == nil {
		err := fmt.Errorf("server did not return a webauthn challenge for %s (cluster second-factor settings?)", user.Username)
		return Result{Phases: phases, Outcome: ClientError}, err
	}

	solveStart := time.Now()
	solved, err := device.SignAssertion(s.origin, &webauthnpb.CredentialAssertion{
		PublicKey: &webauthnpb.PublicKeyCredentialRequestOptions{
			Challenge: beginResp.WebauthnChallenge.Response.Challenge,
			RpId:      beginResp.WebauthnChallenge.Response.RelyingPartyID,
		},
	})
	phases = append(phases, Phase{Name: "mfa-solve", Duration: time.Since(solveStart).Nanoseconds()})
	if err != nil {
		return Result{Phases: phases, Outcome: ClientError}, fmt.Errorf("signing webauthn assertion: %w", err)
	}

	finishStart := time.Now()
	var finishResp sshLoginResponse
	err = postJSON(ctx, s.httpClient, s.baseURL+"/webapi/mfa/login/finish", loginFinishRequest{
		User:                      user.Username,
		Password:                  user.Password,
		WebauthnChallengeResponse: toAssertionResponseWire(solved),
		SSHPubKey:                 kp.SSHPublicKey,
		TLSPubKey:                 kp.TLSPublicKey,
		TTL:                       loginCertTTL,
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

func (s *LocalLoginWebAuthn) Teardown(ctx context.Context) error { return nil }

// toAssertionResponseWire converts our soft device's protobuf-shaped
// output into the JSON wire shape /webapi/mfa/login/finish expects (see
// weblogin.go for why these are two different Go types for the same
// logical response).
func toAssertionResponseWire(r *webauthnpb.CredentialAssertionResponse) *credentialAssertionResponseWire {
	return &credentialAssertionResponseWire{
		ID:    encodeBase64URL(r.RawId),
		Type:  r.Type,
		RawID: r.RawId,
		AssertionResponse: authenticatorAssertionWire{
			ClientDataJSON:    r.Response.ClientDataJson,
			AuthenticatorData: r.Response.AuthenticatorData,
			Signature:         r.Response.Signature,
		},
	}
}
