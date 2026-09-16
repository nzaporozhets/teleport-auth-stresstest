package identity

import (
	"crypto/ecdsa"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/pquerna/otp"

	"teleport-auth-stress/internal/config"
)

// UserFixture is one seeded local user's credentials, as produced by
// authseed apply and consumed by authload's login scenarios. It is the
// only place a user's password and MFA secret material live outside the
// cluster itself.
type UserFixture struct {
	Username     string              `json:"username"`
	Password     string              `json:"password"`
	SecondFactor config.SecondFactor `json:"secondFactor"`

	// WebAuthn devices, present iff SecondFactor == webauthn.
	WebAuthnCredentialID  []byte `json:"webAuthnCredentialID,omitempty"`
	WebAuthnPrivateKeyPEM []byte `json:"webAuthnPrivateKeyPEM,omitempty"`

	// TOTP device, present iff SecondFactor == totp.
	TOTPSecret    string `json:"totpSecret,omitempty"`
	TOTPDigits    uint32 `json:"totpDigits,omitempty"`
	TOTPAlgorithm string `json:"totpAlgorithm,omitempty"`
	TOTPPeriod    uint32 `json:"totpPeriod,omitempty"`
}

// WebAuthnDevice reconstructs the soft authenticator that registered
// this user's WebAuthn device, so a login scenario can answer future
// assertion challenges.
func (u *UserFixture) WebAuthnDevice() (*SoftWebAuthnDevice, error) {
	if u.SecondFactor != config.SecondFactorWebAuthn {
		return nil, fmt.Errorf("user %s has second factor %q, not webauthn", u.Username, u.SecondFactor)
	}
	key, err := parsePrivateKeyPEM(u.WebAuthnPrivateKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("loading WebAuthn key for %s: %w", u.Username, err)
	}
	ecdsaKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("WebAuthn key for %s is %T, want *ecdsa.PrivateKey", u.Username, key)
	}
	return &SoftWebAuthnDevice{CredentialID: u.WebAuthnCredentialID, Key: ecdsaKey}, nil
}

// TOTPDevice reconstructs the soft TOTP authenticator for this user.
func (u *UserFixture) TOTPDevice() (*SoftTOTPDevice, error) {
	if u.SecondFactor != config.SecondFactorTOTP {
		return nil, fmt.Errorf("user %s has second factor %q, not totp", u.Username, u.SecondFactor)
	}
	algo, err := parseTOTPAlgorithm(u.TOTPAlgorithm)
	if err != nil {
		return nil, err
	}
	return &SoftTOTPDevice{
		Secret:    u.TOTPSecret,
		Digits:    otp.Digits(u.TOTPDigits),
		Algorithm: algo,
		Period:    uint(u.TOTPPeriod),
	}, nil
}

// KeyPoolFixture is the persisted form of a KeyPool.
type KeyPoolFixture struct {
	Algorithm      config.KeyAlgorithm `json:"algorithm"`
	PrivateKeyPEMs [][]byte            `json:"privateKeyPEMs"`
}

// FixtureState is everything authseed apply produces and authload needs:
// seeded user credentials and the pre-generated keypair pool. It is
// written to fixtures.statePath. It contains secrets (passwords, WebAuthn
// and TOTP private material) and raw keypair private keys, so it is
// written with 0600 permissions; treat it like the admin identity file.
type FixtureState struct {
	ClusterName  string         `json:"clusterName"`
	GeneratedAt  time.Time      `json:"generatedAt"`
	UserPrefix   string         `json:"userPrefix"`
	Users        []UserFixture  `json:"users"`
	KeyPoolState KeyPoolFixture `json:"keyPool"`
}

// SaveFixtureState writes state as JSON to path, creating parent
// directories as needed.
func SaveFixtureState(path string, state *FixtureState) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling fixture state: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("writing %s: %w", path, err)
	}
	return nil
}

// LoadFixtureState reads a fixture state file written by SaveFixtureState.
func LoadFixtureState(path string) (*FixtureState, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var state FixtureState
	if err := json.Unmarshal(data, &state); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &state, nil
}

// KeyPool reconstructs the in-memory KeyPool from the persisted state.
func (s *FixtureState) KeyPool() (*KeyPool, error) {
	pairs := make([]*KeyPair, len(s.KeyPoolState.PrivateKeyPEMs))
	for i, pemBytes := range s.KeyPoolState.PrivateKeyPEMs {
		kp, err := keyPairFromPrivatePEM(s.KeyPoolState.Algorithm, pemBytes)
		if err != nil {
			return nil, fmt.Errorf("loading key %d/%d from pool: %w", i+1, len(pairs), err)
		}
		pairs[i] = kp
	}
	return KeyPoolFromPairs(s.KeyPoolState.Algorithm, pairs), nil
}
