package identity

import (
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
