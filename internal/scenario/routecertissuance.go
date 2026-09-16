package scenario

import (
	"bytes"
	"context"
	"fmt"
	"sync/atomic"
	"time"

	apiclient "github.com/gravitational/teleport/api/client"
	authproto "github.com/gravitational/teleport/api/client/proto"

	"teleport-auth-stress/internal/config"
	"teleport-auth-stress/internal/identity"
)

// routeCertIssuanceBootstrapTTL/RequestTTL mirror cert-renewal's own
// constants and the same clamp behavior documented there (a plain
// self-request's Expires is capped at the bootstrap cert's own expiry;
// see docs/methodology.md's M2 notes) — this scenario bootstraps and
// requests certs the same way, just with route-scoped usage instead of
// a plain renewal.
const (
	routeCertIssuanceBootstrapTTL = 12 * time.Hour
	routeCertIssuanceRequestTTL   = 30 * time.Minute
)

type routeCertIdentity struct {
	client   *apiclient.Client
	username string
}

// RouteCertIssuance is the "route-cert-issuance" scenario: certificates
// scoped to an app, database, or Kubernetes route. Per instructions.md's
// Scope section, certificate *issuance* for these routes is in scope but
// using them is not — Execute requests and discards a route-scoped cert
// every call, it never dials the app/database/Kubernetes cluster it
// names. This isolates the RBAC route-check + signing cost for a routed
// cert, distinct from cert-renewal's plain self-renewal.
//
// Setup bootstraps identically to CertRenewal.Setup (same impersonation
// requirement and Admin Action MFA caveat — see its comment and
// docs/methodology.md's M2 notes, which apply here unchanged).
type RouteCertIssuance struct {
	identities []routeCertIdentity
	pool       *identity.KeyPool
	route      config.RouteCertIssuance
	next       atomic.Uint64
}

func (s *RouteCertIssuance) Name() string { return "route-cert-issuance" }

func (s *RouteCertIssuance) Setup(ctx context.Context, env *Env) error {
	if env.Admin == nil {
		return fmt.Errorf("route-cert-issuance Setup requires env.Admin for one-time bootstrap issuance")
	}
	if env.Fixtures == nil {
		return fmt.Errorf("route-cert-issuance Setup requires env.Fixtures (run authseed apply first)")
	}
	if env.Config == nil {
		return fmt.Errorf("route-cert-issuance Setup requires env.Config")
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

	identities := make([]routeCertIdentity, 0, n)
	for i := 0; i < n; i++ {
		user := env.Fixtures.Users[i]
		kp := pool.At(i)

		certs, err := env.Admin.GenerateUserCerts(ctx, authproto.UserCertsRequest{
			Username:     user.Username,
			SSHPublicKey: kp.SSHPublicKey,
			TLSPublicKey: kp.TLSPublicKey,
			Expires:      time.Now().Add(routeCertIssuanceBootstrapTTL),
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

		identities = append(identities, routeCertIdentity{client: clt, username: user.Username})
	}

	s.identities = identities
	s.pool = pool
	s.route = env.Config.Load.RouteCertIssuance
	return nil
}

// Execute requests one route-scoped certificate and discards it —
// "issuance only" (see type doc).
func (s *RouteCertIssuance) Execute(ctx context.Context) (Result, error) {
	idx := s.next.Add(1) - 1
	id := s.identities[idx%uint64(len(s.identities))]
	kp := s.pool.At(int(idx))

	req := buildRouteCertsRequest(s.route, id.username, kp.SSHPublicKey, kp.TLSPublicKey)

	start := time.Now()
	_, err := id.client.GenerateUserCerts(ctx, req)
	elapsed := time.Since(start)

	return Result{
		Phases:  []Phase{{Name: "cert-issue", Duration: elapsed.Nanoseconds()}},
		Outcome: ClassifyError(err),
		Bytes:   0,
	}, err
}

func (s *RouteCertIssuance) Teardown(ctx context.Context) error {
	var firstErr error
	for _, id := range s.identities {
		if err := id.client.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// buildRouteCertsRequest builds the UserCertsRequest for one route type.
// Factored out as a pure function (no network, no shared state) so this
// field-setting logic is unit-testable without a live cluster or a fake
// gRPC server.
func buildRouteCertsRequest(route config.RouteCertIssuance, username string, sshPub, tlsPub []byte) authproto.UserCertsRequest {
	req := authproto.UserCertsRequest{
		Username:     username,
		SSHPublicKey: sshPub,
		TLSPublicKey: tlsPub,
		Expires:      time.Now().Add(routeCertIssuanceRequestTTL),
	}
	switch route.RouteType {
	case config.RouteTypeApp:
		req.Usage = authproto.UserCertsRequest_App
		req.RouteToApp = authproto.RouteToApp{Name: route.Target}
	case config.RouteTypeDatabase:
		req.Usage = authproto.UserCertsRequest_Database
		req.RouteToDatabase = authproto.RouteToDatabase{ServiceName: route.Target, Protocol: route.DatabaseProtocol}
	case config.RouteTypeKubernetes:
		req.Usage = authproto.UserCertsRequest_Kubernetes
		req.KubernetesCluster = route.Target
	}
	return req
}
