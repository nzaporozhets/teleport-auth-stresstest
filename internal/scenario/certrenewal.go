package scenario

import (
	"bytes"
	"context"
	"fmt"
	"sync/atomic"
	"time"

	apiclient "github.com/gravitational/teleport/api/client"
	authproto "github.com/gravitational/teleport/api/client/proto"

	"teleport-auth-stress/internal/identity"
)

// bootstrapCertTTL is how long the one-time, admin-issued initial
// certificate is valid for. A self-renewal request's Expires is clamped
// server-side to this original expiry (Teleport v17.7.29,
// lib/auth/auth_with_roles.go: a plain self-request is not "Renewable"
// and its Expires is capped at the session that minted it) — so this
// must comfortably exceed the run duration this scenario will be used
// for, or renewals will start failing near the end of a long run.
const bootstrapCertTTL = 12 * time.Hour

// renewalRequestTTL is the Expires each Execute call requests. It's
// requested honestly (as if this were a real renewal extending validity)
// even though the server won't actually extend past bootstrapCertTTL for
// a non-bot, non-impersonated identity — the point of this scenario is
// the CA-signing/RBAC/backend-read work the call does, not the resulting
// cert's validity window.
const renewalRequestTTL = 30 * time.Minute

// certRenewalIdentity is one virtual user's already-open, already
// self-authenticated connection.
type certRenewalIdentity struct {
	client   *apiclient.Client
	username string
}

// CertRenewal is the "cert-renewal" scenario: gRPC user-certificate
// generation with an already-valid identity, no password hashing. It
// isolates CA signing, RBAC evaluation, and backend reads — see
// instructions.md's scenario table. This is the first scenario
// implemented (M2) because it's the simplest path to a working
// end-to-end driver -> collector -> report pipeline.
//
// Bootstrap (minting each virtual user's first certificate) happens once
// in Setup, using the admin client the driver hands to Setup only.
// Execute renews using nothing but the identity's own previously-issued
// credential, on a connection kept open for the scenario's lifetime
// (matching lib/tbot's own renewal pattern: one long-lived client,
// renewed in place, not reconnected per call) — the admin identity is
// never referenced from Execute, satisfying the guardrail.
type CertRenewal struct {
	identities []certRenewalIdentity
	pool       *identity.KeyPool
	next       atomic.Uint64
}

func (s *CertRenewal) Name() string { return "cert-renewal" }

// Setup bootstraps one certificate per seeded user (up to the key pool's
// size, whichever is smaller) via env.Admin, then opens a long-lived
// client for each using only that bootstrap credential.
//
// Impersonation requirement (cluster setup, not code): env.Admin's
// identity must be allowed to impersonate the seeded users — Teleport
// requires either the builtin Admin role or an explicit
// allow.impersonate rule covering fixtures.roles/users
// (lib/auth/auth_with_roles.go). If the cluster enforces Admin Action
// MFA (second_factor: webauthn without allowing TOTP), a plain local
// admin identity will be asked for an MFA response on every bootstrap
// call; using a Machine ID bot identity for identity.adminIdentityFile
// avoids that entirely (bot and admin-role-impersonated callers are
// exempt) — see docs/runbook.md.
func (s *CertRenewal) Setup(ctx context.Context, env *Env) error {
	if env.Admin == nil {
		return fmt.Errorf("cert-renewal Setup requires env.Admin for one-time bootstrap issuance")
	}
	if env.Fixtures == nil {
		return fmt.Errorf("cert-renewal Setup requires env.Fixtures (run authseed apply first)")
	}

	pool, err := env.Fixtures.KeyPool()
	if err != nil {
		return fmt.Errorf("loading key pool: %w", err)
	}
	if pool.Size() == 0 {
		return fmt.Errorf("key pool is empty")
	}
	if len(env.Fixtures.Users) == 0 {
		return fmt.Errorf("no seeded users in fixture state; run authseed apply first")
	}

	n := len(env.Fixtures.Users)
	if pool.Size() < n {
		n = pool.Size()
	}

	identities := make([]certRenewalIdentity, 0, n)
	for i := 0; i < n; i++ {
		user := env.Fixtures.Users[i]
		kp := pool.At(i)

		certs, err := env.Admin.GenerateUserCerts(ctx, authproto.UserCertsRequest{
			Username:     user.Username,
			SSHPublicKey: kp.SSHPublicKey,
			TLSPublicKey: kp.TLSPublicKey,
			Expires:      time.Now().Add(bootstrapCertTTL),
		})
		if err != nil {
			return fmt.Errorf("bootstrapping certificate for %s: %w", user.Username, err)
		}

		keyPEM, err := kp.PrivateKeyPEM()
		if err != nil {
			return fmt.Errorf("encoding bootstrap key for %s: %w", user.Username, err)
		}
		creds, err := apiclient.KeyPair(certs.TLS, keyPEM, bytes.Join(certs.TLSCACerts, nil))
		if err != nil {
			return fmt.Errorf("building credentials for %s: %w", user.Username, err)
		}

		clt, err := identity.NewClient(ctx, env.Config, creds)
		if err != nil {
			return fmt.Errorf("connecting as %s: %w", user.Username, err)
		}

		identities = append(identities, certRenewalIdentity{client: clt, username: user.Username})
	}

	s.identities = identities
	s.pool = pool
	return nil
}

// Execute renews one identity's certificate: draws the next keypair from
// the pool (domain constraint #4 — never generate one inline) and asks
// that identity's own already-open connection to sign it for itself.
func (s *CertRenewal) Execute(ctx context.Context) (Result, error) {
	idx := s.next.Add(1) - 1
	id := s.identities[idx%uint64(len(s.identities))]
	kp := s.pool.At(int(idx))

	start := time.Now()
	_, err := id.client.GenerateUserCerts(ctx, authproto.UserCertsRequest{
		Username:     id.username,
		SSHPublicKey: kp.SSHPublicKey,
		TLSPublicKey: kp.TLSPublicKey,
		Expires:      time.Now().Add(renewalRequestTTL),
	})
	elapsed := time.Since(start)

	return Result{
		Phases:  []Phase{{Name: "cert-issue", Duration: elapsed.Nanoseconds()}},
		Outcome: ClassifyError(err),
		Bytes:   0,
	}, err
}

// Teardown closes every identity's connection.
func (s *CertRenewal) Teardown(ctx context.Context) error {
	var firstErr error
	for _, id := range s.identities {
		if err := id.client.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
