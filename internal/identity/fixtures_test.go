package identity

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	webauthnpb "github.com/gravitational/teleport/api/types/webauthn"

	"teleport-auth-stress/internal/config"
)

func TestFixtureState_SaveLoadRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "fixtures.json")

	waDevice, err := NewSoftWebAuthnDevice()
	if err != nil {
		t.Fatalf("NewSoftWebAuthnDevice: %v", err)
	}
	waKeyPEM, err := marshalPrivateKeyPEM(waDevice.Key)
	if err != nil {
		t.Fatalf("marshalPrivateKeyPEM: %v", err)
	}

	pool, err := GenerateKeyPool(config.KeyAlgorithmECDSA, 2)
	if err != nil {
		t.Fatalf("GenerateKeyPool: %v", err)
	}
	pemKeys := make([][]byte, pool.Size())
	for i, kp := range pool.Pairs() {
		pemKeys[i], err = marshalPrivateKeyPEM(kp.Private)
		if err != nil {
			t.Fatalf("marshalPrivateKeyPEM: %v", err)
		}
	}

	original := &FixtureState{
		ClusterName: "loadtest",
		UserPrefix:  "stress-",
		Users: []UserFixture{
			{
				Username:              "stress-00000",
				Password:              "s3cret",
				SecondFactor:          config.SecondFactorWebAuthn,
				WebAuthnCredentialID:  waDevice.CredentialID,
				WebAuthnPrivateKeyPEM: waKeyPEM,
			},
			{
				Username:      "stress-00001",
				Password:      "s3cret2",
				SecondFactor:  config.SecondFactorTOTP,
				TOTPSecret:    "JBSWY3DPEHPK3PXP",
				TOTPDigits:    6,
				TOTPAlgorithm: "SHA1",
				TOTPPeriod:    30,
			},
		},
		KeyPoolState: KeyPoolFixture{
			Algorithm:      config.KeyAlgorithmECDSA,
			PrivateKeyPEMs: pemKeys,
		},
	}

	if err := SaveFixtureState(path, original); err != nil {
		t.Fatalf("SaveFixtureState: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("fixture state file permissions = %o, want 0600 (it contains secrets)", perm)
	}

	loaded, err := LoadFixtureState(path)
	if err != nil {
		t.Fatalf("LoadFixtureState: %v", err)
	}

	if loaded.ClusterName != original.ClusterName || loaded.UserPrefix != original.UserPrefix {
		t.Errorf("top-level fields did not round-trip: %+v", loaded)
	}
	if len(loaded.Users) != 2 {
		t.Fatalf("got %d users, want 2", len(loaded.Users))
	}

	waUser := loaded.Users[0]
	device, err := waUser.WebAuthnDevice()
	if err != nil {
		t.Fatalf("WebAuthnDevice: %v", err)
	}
	// Sanity: the reconstructed device can still answer a challenge.
	if _, err := device.SignAssertion("https://example.com", &webauthnpb.CredentialAssertion{
		PublicKey: &webauthnpb.PublicKeyCredentialRequestOptions{Challenge: []byte("chal"), RpId: "example.com"},
	}); err != nil {
		t.Errorf("reconstructed WebAuthn device failed to sign: %v", err)
	}

	totpUser := loaded.Users[1]
	totpDevice, err := totpUser.TOTPDevice()
	if err != nil {
		t.Fatalf("TOTPDevice: %v", err)
	}
	if _, err := totpDevice.Code(time.Now()); err != nil {
		t.Errorf("reconstructed TOTP device failed to generate a code: %v", err)
	}

	reconstructedPool, err := loaded.KeyPool()
	if err != nil {
		t.Fatalf("KeyPool: %v", err)
	}
	if reconstructedPool.Size() != 2 {
		t.Errorf("KeyPool size = %d, want 2", reconstructedPool.Size())
	}
}

func TestUserFixture_WrongSecondFactorRejected(t *testing.T) {
	u := &UserFixture{Username: "x", SecondFactor: config.SecondFactorNone}
	if _, err := u.WebAuthnDevice(); err == nil {
		t.Error("expected error requesting WebAuthnDevice() for a none-second-factor user")
	}
	if _, err := u.TOTPDevice(); err == nil {
		t.Error("expected error requesting TOTPDevice() for a none-second-factor user")
	}
}

func TestShardUsers_DisjointAndComplete(t *testing.T) {
	users := make([]UserFixture, 10)
	for i := range users {
		users[i] = UserFixture{Username: fmt.Sprintf("stress-%05d", i)}
	}

	const shardCount = 3
	seen := make(map[string]int)
	total := 0
	for i := 0; i < shardCount; i++ {
		shard := ShardUsers(users, i, shardCount)
		total += len(shard)
		for _, u := range shard {
			seen[u.Username]++
		}
	}

	if total != len(users) {
		t.Errorf("sum of shard sizes = %d, want %d", total, len(users))
	}
	for name, count := range seen {
		if count != 1 {
			t.Errorf("user %s assigned to %d shards, want exactly 1", name, count)
		}
	}
}

func TestShardUsers_SinglePodReturnsAll(t *testing.T) {
	users := []UserFixture{{Username: "a"}, {Username: "b"}}
	shard := ShardUsers(users, 0, 1)
	if len(shard) != len(users) {
		t.Errorf("ShardUsers(users, 0, 1) returned %d users, want %d", len(shard), len(users))
	}
}

func TestFixtureState_Shard_KeepsUserAndKeyPairingConsistent(t *testing.T) {
	pool, err := GenerateKeyPool(config.KeyAlgorithmEd25519, 9)
	if err != nil {
		t.Fatalf("GenerateKeyPool: %v", err)
	}
	pemKeys := make([][]byte, pool.Size())
	for i, kp := range pool.Pairs() {
		pemKeys[i], err = kp.PrivateKeyPEM()
		if err != nil {
			t.Fatalf("PrivateKeyPEM: %v", err)
		}
	}

	users := make([]UserFixture, 9)
	for i := range users {
		users[i] = UserFixture{Username: fmt.Sprintf("stress-%05d", i)}
	}

	full := &FixtureState{
		ClusterName:  "loadtest",
		Users:        users,
		KeyPoolState: KeyPoolFixture{Algorithm: config.KeyAlgorithmEd25519, PrivateKeyPEMs: pemKeys},
	}

	const shardCount = 3
	totalUsers, totalKeys := 0, 0
	for i := 0; i < shardCount; i++ {
		shard := full.Shard(i, shardCount)
		if shard.ClusterName != "loadtest" {
			t.Errorf("shard %d ClusterName = %q, want preserved value", i, shard.ClusterName)
		}
		if len(shard.Users) != len(shard.KeyPoolState.PrivateKeyPEMs) {
			t.Errorf("shard %d has %d users but %d keys, want equal counts (1:1 pairing preserved)", i, len(shard.Users), len(shard.KeyPoolState.PrivateKeyPEMs))
		}
		totalUsers += len(shard.Users)
		totalKeys += len(shard.KeyPoolState.PrivateKeyPEMs)
	}
	if totalUsers != len(users) {
		t.Errorf("sum of shard user counts = %d, want %d", totalUsers, len(users))
	}
	if totalKeys != len(pemKeys) {
		t.Errorf("sum of shard key counts = %d, want %d", totalKeys, len(pemKeys))
	}
}

func TestFixtureState_Shard_SinglePodReturnsSelf(t *testing.T) {
	full := &FixtureState{Users: []UserFixture{{Username: "a"}}}
	if full.Shard(0, 1) != full {
		t.Error("Shard(0, 1) should return the same FixtureState unchanged")
	}
}
