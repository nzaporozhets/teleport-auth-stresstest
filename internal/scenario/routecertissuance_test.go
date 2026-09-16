package scenario

import (
	"context"
	"testing"

	authproto "github.com/gravitational/teleport/api/client/proto"

	"teleport-auth-stress/internal/config"
	"teleport-auth-stress/internal/identity"
)

func TestRouteCertIssuance_Name(t *testing.T) {
	s := &RouteCertIssuance{}
	if s.Name() != "route-cert-issuance" {
		t.Errorf("Name() = %q, want route-cert-issuance", s.Name())
	}
}

// These guard-clause tests need no live cluster, matching
// certrenewal_test.go's approach for the same reason: Setup must fail
// fast and clearly, before attempting any network call, when it's
// missing what it needs.

func TestRouteCertIssuance_Setup_RequiresAdmin(t *testing.T) {
	s := &RouteCertIssuance{}
	err := s.Setup(context.Background(), &Env{
		Config:   &config.Config{},
		Fixtures: &identity.FixtureState{Users: []identity.UserFixture{{Username: "u"}}},
	})
	if err == nil {
		t.Fatal("expected error when env.Admin is nil")
	}
}

func TestRouteCertIssuance_Setup_RequiresFixtures(t *testing.T) {
	s := &RouteCertIssuance{}
	err := s.Setup(context.Background(), &Env{Config: &config.Config{}, Admin: &identity.AdminClient{}})
	if err == nil {
		t.Fatal("expected error when env.Fixtures is nil")
	}
}

func TestRouteCertIssuance_Setup_RequiresConfig(t *testing.T) {
	s := &RouteCertIssuance{}
	err := s.Setup(context.Background(), &Env{
		Admin:    &identity.AdminClient{},
		Fixtures: &identity.FixtureState{Users: []identity.UserFixture{{Username: "u"}}},
	})
	if err == nil {
		t.Fatal("expected error when env.Config is nil")
	}
}

func TestRouteCertIssuance_Setup_RequiresNonEmptyKeyPool(t *testing.T) {
	s := &RouteCertIssuance{}
	err := s.Setup(context.Background(), &Env{
		Admin:  &identity.AdminClient{},
		Config: &config.Config{},
		Fixtures: &identity.FixtureState{
			Users:        []identity.UserFixture{{Username: "u"}},
			KeyPoolState: identity.KeyPoolFixture{Algorithm: config.KeyAlgorithmEd25519},
		},
	})
	if err == nil {
		t.Fatal("expected error when the key pool is empty")
	}
}

func TestRouteCertIssuance_Setup_RequiresSeededUsers(t *testing.T) {
	kp, err := identity.GenerateKeyPair(config.KeyAlgorithmEd25519)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	keyPEM, err := kp.PrivateKeyPEM()
	if err != nil {
		t.Fatalf("PrivateKeyPEM: %v", err)
	}

	s := &RouteCertIssuance{}
	err = s.Setup(context.Background(), &Env{
		Admin:  &identity.AdminClient{},
		Config: &config.Config{},
		Fixtures: &identity.FixtureState{
			KeyPoolState: identity.KeyPoolFixture{Algorithm: config.KeyAlgorithmEd25519, PrivateKeyPEMs: [][]byte{keyPEM}},
		},
	})
	if err == nil {
		t.Fatal("expected error when there are no seeded users")
	}
}

func TestRouteCertIssuance_Teardown_NoIdentitiesIsNoop(t *testing.T) {
	s := &RouteCertIssuance{}
	if err := s.Teardown(context.Background()); err != nil {
		t.Errorf("Teardown with no identities should be a no-op, got: %v", err)
	}
}

func TestBuildRouteCertsRequest_App(t *testing.T) {
	req := buildRouteCertsRequest(config.RouteCertIssuance{RouteType: config.RouteTypeApp, Target: "my-app"}, "stress-00000", []byte("ssh"), []byte("tls"))
	if req.Usage != authproto.UserCertsRequest_App {
		t.Errorf("Usage = %v, want App", req.Usage)
	}
	if req.RouteToApp.Name != "my-app" {
		t.Errorf("RouteToApp.Name = %q, want my-app", req.RouteToApp.Name)
	}
	if req.Username != "stress-00000" {
		t.Errorf("Username = %q, want stress-00000", req.Username)
	}
}

func TestBuildRouteCertsRequest_Database(t *testing.T) {
	req := buildRouteCertsRequest(config.RouteCertIssuance{RouteType: config.RouteTypeDatabase, Target: "pg", DatabaseProtocol: "postgres"}, "u", nil, nil)
	if req.Usage != authproto.UserCertsRequest_Database {
		t.Errorf("Usage = %v, want Database", req.Usage)
	}
	if req.RouteToDatabase.ServiceName != "pg" || req.RouteToDatabase.Protocol != "postgres" {
		t.Errorf("RouteToDatabase = %+v, want ServiceName=pg Protocol=postgres", req.RouteToDatabase)
	}
}

func TestBuildRouteCertsRequest_Kubernetes(t *testing.T) {
	req := buildRouteCertsRequest(config.RouteCertIssuance{RouteType: config.RouteTypeKubernetes, Target: "my-cluster"}, "u", nil, nil)
	if req.Usage != authproto.UserCertsRequest_Kubernetes {
		t.Errorf("Usage = %v, want Kubernetes", req.Usage)
	}
	if req.KubernetesCluster != "my-cluster" {
		t.Errorf("KubernetesCluster = %q, want my-cluster", req.KubernetesCluster)
	}
}
