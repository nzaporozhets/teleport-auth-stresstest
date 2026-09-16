package scenario

import (
	"context"
	"testing"

	"teleport-auth-stress/internal/config"
	"teleport-auth-stress/internal/identity"
)

func TestBotJoinRenew_Name(t *testing.T) {
	s := &BotJoinRenew{}
	if s.Name() != "bot-join-renew" {
		t.Errorf("Name() = %q, want bot-join-renew", s.Name())
	}
}

func TestBotResourceName(t *testing.T) {
	cases := map[string]string{
		"my-bot":     "bot-my-bot",
		"has spaces": "bot-has-spaces",
	}
	for in, want := range cases {
		if got := botResourceName(in); got != want {
			t.Errorf("botResourceName(%q) = %q, want %q", in, got, want)
		}
	}
}

// These guard-clause tests need no live cluster, matching
// certrenewal_test.go's approach: Setup must fail fast and clearly,
// before attempting any network call, when it's missing what it needs.

func TestBotJoinRenew_Setup_RequiresAdmin(t *testing.T) {
	s := &BotJoinRenew{}
	err := s.Setup(context.Background(), &Env{
		Config:   &config.Config{},
		Fixtures: &identity.FixtureState{},
	})
	if err == nil {
		t.Fatal("expected error when env.Admin is nil")
	}
}

func TestBotJoinRenew_Setup_RequiresFixtures(t *testing.T) {
	s := &BotJoinRenew{}
	err := s.Setup(context.Background(), &Env{Config: &config.Config{}, Admin: &identity.AdminClient{}})
	if err == nil {
		t.Fatal("expected error when env.Fixtures is nil")
	}
}

func TestBotJoinRenew_Setup_RequiresConfig(t *testing.T) {
	s := &BotJoinRenew{}
	err := s.Setup(context.Background(), &Env{Admin: &identity.AdminClient{}, Fixtures: &identity.FixtureState{}})
	if err == nil {
		t.Fatal("expected error when env.Config is nil")
	}
}

func TestBotJoinRenew_Setup_RequiresNonEmptyKeyPool(t *testing.T) {
	s := &BotJoinRenew{}
	err := s.Setup(context.Background(), &Env{
		Admin:  &identity.AdminClient{},
		Config: &config.Config{},
		Fixtures: &identity.FixtureState{
			KeyPoolState: identity.KeyPoolFixture{Algorithm: config.KeyAlgorithmEd25519},
		},
	})
	if err == nil {
		t.Fatal("expected error when the key pool is empty")
	}
}

func TestBotJoinRenew_Setup_RequiresPositiveBotCount(t *testing.T) {
	kp, err := identity.GenerateKeyPair(config.KeyAlgorithmEd25519)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	keyPEM, err := kp.PrivateKeyPEM()
	if err != nil {
		t.Fatalf("PrivateKeyPEM: %v", err)
	}

	s := &BotJoinRenew{}
	// BotCount and UserCount both zero, so the effective bot count is 0.
	err = s.Setup(context.Background(), &Env{
		Admin:  &identity.AdminClient{},
		Config: &config.Config{},
		Fixtures: &identity.FixtureState{
			KeyPoolState: identity.KeyPoolFixture{Algorithm: config.KeyAlgorithmEd25519, PrivateKeyPEMs: [][]byte{keyPEM}},
		},
	})
	if err == nil {
		t.Fatal("expected error when fixtures.botCount and fixtures.userCount are both 0")
	}
}

func TestBotJoinRenew_Teardown_NoIdentitiesIsNoop(t *testing.T) {
	s := &BotJoinRenew{}
	if err := s.Teardown(context.Background()); err != nil {
		t.Errorf("Teardown with no identities should be a no-op, got: %v", err)
	}
}
