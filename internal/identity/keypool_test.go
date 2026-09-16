package identity

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"golang.org/x/crypto/ssh"

	"teleport-auth-stress/internal/config"
)

func TestKeyGenCount_TracksGenerateKeyPairCalls(t *testing.T) {
	ResetKeyGenCount()
	if KeyGenCount() != 0 {
		t.Fatalf("KeyGenCount() after reset = %d, want 0", KeyGenCount())
	}
	if _, err := GenerateKeyPair(config.KeyAlgorithmEd25519); err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if _, err := GenerateKeyPair(config.KeyAlgorithmEd25519); err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	if got := KeyGenCount(); got != 2 {
		t.Errorf("KeyGenCount() = %d, want 2", got)
	}
}

func TestGenerateKeyPair_AllAlgorithms(t *testing.T) {
	for _, algo := range []config.KeyAlgorithm{config.KeyAlgorithmECDSA, config.KeyAlgorithmEd25519, config.KeyAlgorithmRSA2048} {
		t.Run(string(algo), func(t *testing.T) {
			kp, err := GenerateKeyPair(algo)
			if err != nil {
				t.Fatalf("GenerateKeyPair(%s): %v", algo, err)
			}

			if _, _, _, _, err := ssh.ParseAuthorizedKey(kp.SSHPublicKey); err != nil {
				t.Errorf("SSHPublicKey not parseable: %v", err)
			}

			block, _ := pem.Decode(kp.TLSPublicKey)
			if block == nil {
				t.Fatal("TLSPublicKey has no PEM block")
			}
			if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
				t.Errorf("TLSPublicKey not parseable: %v", err)
			}

			// Round-trip the private key through PEM, as fixtures.go does.
			pemBytes, err := marshalPrivateKeyPEM(kp.Private)
			if err != nil {
				t.Fatalf("marshalPrivateKeyPEM: %v", err)
			}
			if _, err := parsePrivateKeyPEM(pemBytes); err != nil {
				t.Errorf("parsePrivateKeyPEM: %v", err)
			}
		})
	}
}

func TestGenerateKeyPair_UnsupportedAlgorithm(t *testing.T) {
	if _, err := GenerateKeyPair("bogus"); err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}

func TestKeyPool_SizeAndWraparound(t *testing.T) {
	pool, err := GenerateKeyPool(config.KeyAlgorithmEd25519, 3)
	if err != nil {
		t.Fatalf("GenerateKeyPool: %v", err)
	}
	if pool.Size() != 3 {
		t.Fatalf("Size() = %d, want 3", pool.Size())
	}
	// At() must wrap around rather than panic.
	first := pool.At(0)
	wrapped := pool.At(3)
	if first != wrapped {
		t.Errorf("At(3) should wrap to At(0)'s entry")
	}
}

func TestGenerateKeyPool_RejectsNonPositiveSize(t *testing.T) {
	if _, err := GenerateKeyPool(config.KeyAlgorithmEd25519, 0); err == nil {
		t.Fatal("expected error for size 0")
	}
}

func TestKeyPairFromPrivatePEM_MatchesOriginal(t *testing.T) {
	original, err := GenerateKeyPair(config.KeyAlgorithmECDSA)
	if err != nil {
		t.Fatalf("GenerateKeyPair: %v", err)
	}
	pemBytes, err := marshalPrivateKeyPEM(original.Private)
	if err != nil {
		t.Fatalf("marshalPrivateKeyPEM: %v", err)
	}

	reconstructed, err := keyPairFromPrivatePEM(config.KeyAlgorithmECDSA, pemBytes)
	if err != nil {
		t.Fatalf("keyPairFromPrivatePEM: %v", err)
	}
	if string(reconstructed.SSHPublicKey) != string(original.SSHPublicKey) {
		t.Errorf("SSH public key mismatch after round-trip")
	}
	if string(reconstructed.TLSPublicKey) != string(original.TLSPublicKey) {
		t.Errorf("TLS public key mismatch after round-trip")
	}
}
