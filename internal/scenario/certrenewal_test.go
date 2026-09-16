package scenario

import (
	"context"
	"testing"

	"teleport-auth-stress/internal/config"
	"teleport-auth-stress/internal/identity"
)

func TestCertRenewal_Name(t *testing.T) {
	s := &CertRenewal{}
	if s.Name() != "cert-renewal" {
		t.Errorf("Name() = %q, want cert-renewal", s.Name())
	}
}

// These guard-clause tests need no live cluster: Setup must fail fast
// and clearly, before attempting any network call, when it's missing
// what it needs.

func TestCertRenewal_Setup_RequiresAdmin(t *testing.T) {
	s := &CertRenewal{}
	err := s.Setup(context.Background(), &Env{Fixtures: &identity.FixtureState{
		Users:        []identity.UserFixture{{Username: "u"}},
		KeyPoolState: identity.KeyPoolFixture{Algorithm: config.KeyAlgorithmEd25519, PrivateKeyPEMs: [][]byte{{}}},
	}})
	if err == nil {
		t.Fatal("expected error when env.Admin is nil")
	}
}

func TestCertRenewal_Setup_RequiresFixtures(t *testing.T) {
	s := &CertRenewal{}
	err := s.Setup(context.Background(), &Env{Admin: &identity.AdminClient{}})
	if err == nil {
		t.Fatal("expected error when env.Fixtures is nil")
	}
}

func TestCertRenewal_Setup_RequiresNonEmptyKeyPool(t *testing.T) {
	s := &CertRenewal{}
	err := s.Setup(context.Background(), &Env{
		Admin: &identity.AdminClient{},
		Fixtures: &identity.FixtureState{
			Users:        []identity.UserFixture{{Username: "u"}},
			KeyPoolState: identity.KeyPoolFixture{Algorithm: config.KeyAlgorithmEd25519},
		},
	})
	if err == nil {
		t.Fatal("expected error when the key pool is empty")
	}
}

func TestCertRenewal_Setup_RequiresSeededUsers(t *testing.T) {
	kp, err := identity.GenerateKeyPair(config.KeyAlgorithmEd25519)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	keyPEM, err := kp.PrivateKeyPEM()
	if err != nil {
		t.Fatalf("PrivateKeyPEM: %v", err)
	}

	s := &CertRenewal{}
	err = s.Setup(context.Background(), &Env{
		Admin: &identity.AdminClient{},
		Fixtures: &identity.FixtureState{
			KeyPoolState: identity.KeyPoolFixture{Algorithm: config.KeyAlgorithmEd25519, PrivateKeyPEMs: [][]byte{keyPEM}},
		},
	})
	if err == nil {
		t.Fatal("expected error when there are no seeded users")
	}
}

func TestCertRenewal_Teardown_NoIdentitiesIsNoop(t *testing.T) {
	s := &CertRenewal{}
	if err := s.Teardown(context.Background()); err != nil {
		t.Errorf("Teardown with no identities should be a no-op, got: %v", err)
	}
}
