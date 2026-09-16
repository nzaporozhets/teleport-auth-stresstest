// Package identity provides the pieces authseed uses to provision
// fixtures and authload uses to drive load: an admin client wrapper, a
// pre-generated keypair pool, and soft (in-process) WebAuthn/TOTP
// authenticators. See instructions.md "Architecture" and domain
// constraint #4 (client-side key generation is not part of the server's
// work — keys are generated here, once, not in any scenario's Execute).
package identity

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"sync/atomic"

	"golang.org/x/crypto/ssh"

	"teleport-auth-stress/internal/config"
)

// keyGenCount counts every GenerateKeyPair call process-wide. It exists
// so tests can prove, directly rather than by inference from allocation
// counts, that a scenario's Execute never generates a keypair inline
// (domain constraint #4) — see KeyGenCount / ResetKeyGenCount and the M3
// acceptance test in internal/scenario.
var keyGenCount atomic.Int64

// KeyGenCount returns how many keypairs GenerateKeyPair has produced
// since the last ResetKeyGenCount (or process start).
func KeyGenCount() int64 { return keyGenCount.Load() }

// ResetKeyGenCount zeroes the counter. Tests call this right before the
// code path under test so any subsequent GenerateKeyPair call is
// unambiguously attributable to that path.
func ResetKeyGenCount() { keyGenCount.Store(0) }

// KeyPair is one pre-generated keypair, encoded in the two forms
// Teleport's client APIs consume: SSH authorized-keys format for
// UserCertsRequest.SSHPublicKey / AuthenticateSSHUserRequest.SSHPubKey,
// and PEM/PKIX for the TLS-side public key. authseed apply persists the
// whole pool (including private keys, PKCS8-PEM-encoded) to
// fixtures.statePath so authload can load it once at process start and
// draw from it in the hot path without ever generating a key inline
// (domain constraint #4) — see fixtures.go.
type KeyPair struct {
	Algorithm    config.KeyAlgorithm
	Private      crypto.Signer
	SSHPublicKey []byte // authorized_keys format
	TLSPublicKey []byte // PEM, PKIX
}

// PrivateKeyPEM PKCS8-encodes the private key, for callers outside this
// package that need to build a client.KeyPair credential (e.g. a
// scenario's Setup bootstrapping a per-identity connection).
func (kp *KeyPair) PrivateKeyPEM() ([]byte, error) {
	return marshalPrivateKeyPEM(kp.Private)
}

// GenerateKeyPair creates one keypair of the given algorithm. Called only
// during authseed apply / scenario Setup — never from a scenario's
// Execute (domain constraint #4).
func GenerateKeyPair(algo config.KeyAlgorithm) (*KeyPair, error) {
	keyGenCount.Add(1)

	var signer crypto.Signer
	var err error

	switch algo {
	case config.KeyAlgorithmECDSA:
		signer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case config.KeyAlgorithmEd25519:
		_, signer, err = ed25519.GenerateKey(rand.Reader)
	case config.KeyAlgorithmRSA2048:
		signer, err = rsa.GenerateKey(rand.Reader, 2048)
	default:
		return nil, fmt.Errorf("unsupported key algorithm %q", algo)
	}
	if err != nil {
		return nil, fmt.Errorf("generating %s key: %w", algo, err)
	}

	sshPub, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("converting %s public key to SSH format: %w", algo, err)
	}

	tlsPubDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("marshalling %s public key to PKIX: %w", algo, err)
	}
	tlsPub := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: tlsPubDER})

	return &KeyPair{
		Algorithm:    algo,
		Private:      signer,
		SSHPublicKey: ssh.MarshalAuthorizedKey(sshPub),
		TLSPublicKey: tlsPub,
	}, nil
}

// KeyPool is an in-memory pool of pre-generated keypairs. Scenarios draw
// from it via Take rather than generating keys inline.
type KeyPool struct {
	Algorithm config.KeyAlgorithm
	pairs     []*KeyPair
}

// GenerateKeyPool creates a pool of n keypairs of the given algorithm.
func GenerateKeyPool(algo config.KeyAlgorithm, n int) (*KeyPool, error) {
	if n <= 0 {
		return nil, fmt.Errorf("key pool size must be > 0, got %d", n)
	}
	pairs := make([]*KeyPair, n)
	for i := range pairs {
		kp, err := GenerateKeyPair(algo)
		if err != nil {
			return nil, fmt.Errorf("generating key %d/%d: %w", i+1, n, err)
		}
		pairs[i] = kp
	}
	return &KeyPool{Algorithm: algo, pairs: pairs}, nil
}

// Size reports how many keypairs are in the pool.
func (p *KeyPool) Size() int { return len(p.pairs) }

// At returns the keypair at index i, wrapping around the pool so callers
// can draw more times than the pool has entries.
func (p *KeyPool) At(i int) *KeyPair {
	return p.pairs[i%len(p.pairs)]
}

// Pairs exposes the underlying slice for persistence (fixtures.go) and
// tests. Callers must not mutate it.
func (p *KeyPool) Pairs() []*KeyPair { return p.pairs }

// Shard returns the disjoint slice of this pool assigned to pod `index`
// out of `count` pods (instructions.md "Distributed execution": each
// generator pod gets "a disjoint slice of the seeded user pool"; the
// same principle applies to the keypair pool so two pods never spend
// admin-assisted bootstrap effort on the same keypair). Interleaved
// (index, index+count, index+2*count, ...) rather than contiguous
// chunks, so an uneven division spreads the remainder across pods
// instead of piling it onto the last one.
func (p *KeyPool) Shard(index, count int) *KeyPool {
	if count <= 1 {
		return p
	}
	var shard []*KeyPair
	for i := index; i < len(p.pairs); i += count {
		shard = append(shard, p.pairs[i])
	}
	return &KeyPool{Algorithm: p.Algorithm, pairs: shard}
}

// KeyPoolFromPairs reconstructs a KeyPool from previously-persisted
// keypairs (fixtures.go LoadFixtureState).
func KeyPoolFromPairs(algo config.KeyAlgorithm, pairs []*KeyPair) *KeyPool {
	return &KeyPool{Algorithm: algo, pairs: pairs}
}

// marshalPrivateKeyPEM PKCS8-encodes a private key for persistence.
func marshalPrivateKeyPEM(signer crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(signer)
	if err != nil {
		return nil, fmt.Errorf("marshalling private key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// parsePrivateKeyPEM decodes a PKCS8 PEM-encoded private key produced by
// marshalPrivateKeyPEM.
func parsePrivateKeyPEM(pemBytes []byte) (crypto.Signer, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found in private key")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing PKCS8 private key: %w", err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("parsed private key of type %T does not implement crypto.Signer", key)
	}
	return signer, nil
}

// keyPairFromPrivatePEM reconstructs a full KeyPair (including derived
// SSH/TLS public-key encodings) from a persisted private key, so
// FixtureState.KeyPool doesn't need to separately persist public keys.
func keyPairFromPrivatePEM(algo config.KeyAlgorithm, pemBytes []byte) (*KeyPair, error) {
	signer, err := parsePrivateKeyPEM(pemBytes)
	if err != nil {
		return nil, err
	}

	sshPub, err := ssh.NewPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("converting %s public key to SSH format: %w", algo, err)
	}
	tlsPubDER, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return nil, fmt.Errorf("marshalling %s public key to PKIX: %w", algo, err)
	}

	return &KeyPair{
		Algorithm:    algo,
		Private:      signer,
		SSHPublicKey: ssh.MarshalAuthorizedKey(sshPub),
		TLSPublicKey: pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: tlsPubDER}),
	}, nil
}
