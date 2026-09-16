package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"

	webauthnpb "github.com/gravitational/teleport/api/types/webauthn"
)

// SoftWebAuthnDevice is an in-process software WebAuthn authenticator: it
// answers registration and assertion challenges the same way a real
// security key would, without any browser or hardware. This is the
// "soft WebAuthn authenticator" domain constraint #1 calls for — WebAuthn
// has no replay-window limit (unlike TOTP), so it's the primary login
// scenario's second factor.
//
// It is intentionally hand-rolled against the public wire types
// (api/types/webauthn) rather than importing Teleport's own test
// authenticator (lib/auth/mocku2f), which lives outside the api/ module
// boundary and carries no compatibility guarantee. See docs/methodology.md.
type SoftWebAuthnDevice struct {
	CredentialID []byte
	Key          *ecdsa.PrivateKey
	counter      uint32
}

// NewSoftWebAuthnDevice creates a device with a fresh ES256 (P-256)
// keypair and a random credential ID, ready to answer one registration
// challenge and any number of subsequent assertion challenges.
func NewSoftWebAuthnDevice() (*SoftWebAuthnDevice, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating WebAuthn device key: %w", err)
	}
	credID := make([]byte, 32)
	if _, err := rand.Read(credID); err != nil {
		return nil, fmt.Errorf("generating WebAuthn credential ID: %w", err)
	}
	return &SoftWebAuthnDevice{CredentialID: credID, Key: key}, nil
}

const (
	flagUserPresent    byte = 0x01
	flagUserVerified   byte = 0x04
	flagAttestedCredID byte = 0x40
)

type clientData struct {
	Type      string `json:"type"`
	Challenge string `json:"challenge"`
	Origin    string `json:"origin"`
}

func buildClientDataJSON(typ string, challenge []byte, origin string) []byte {
	b, _ := json.Marshal(clientData{
		Type:      typ,
		Challenge: base64.RawURLEncoding.EncodeToString(challenge),
		Origin:    origin,
	})
	return b
}

// buildAuthData assembles the WebAuthn authenticatorData structure:
// rpIdHash(32) || flags(1) || counter(4) || attestedCredentialData(var,
// registration only). https://www.w3.org/TR/webauthn-2/#authenticator-data
func buildAuthData(rpID string, flags byte, counter uint32, attestedCredData []byte) []byte {
	rpHash := sha256.Sum256([]byte(rpID))
	buf := make([]byte, 0, 37+len(attestedCredData))
	buf = append(buf, rpHash[:]...)
	buf = append(buf, flags)
	var ctr [4]byte
	binary.BigEndian.PutUint32(ctr[:], counter)
	buf = append(buf, ctr[:]...)
	buf = append(buf, attestedCredData...)
	return buf
}

// SignRegistration answers a registration (CreateCredential) challenge,
// as if a security key had just been touched.
func (d *SoftWebAuthnDevice) SignRegistration(origin string, cc *webauthnpb.CredentialCreation) (*webauthnpb.CredentialCreationResponse, error) {
	if cc.GetPublicKey() == nil {
		return nil, fmt.Errorf("registration challenge has no public key options")
	}
	rpID := cc.GetPublicKey().GetRp().GetId()
	clientDataJSON := buildClientDataJSON("webauthn.create", cc.GetPublicKey().GetChallenge(), origin)

	pub := d.Key.PublicKey
	coseKey := coseKeyEC2(pub.X.FillBytes(make([]byte, 32)), pub.Y.FillBytes(make([]byte, 32)))

	var credIDLen [2]byte
	binary.BigEndian.PutUint16(credIDLen[:], uint16(len(d.CredentialID)))
	attestedCredData := make([]byte, 0, 16+2+len(d.CredentialID)+len(coseKey))
	attestedCredData = append(attestedCredData, make([]byte, 16)...) // AAGUID: zero, we're not a real authenticator model
	attestedCredData = append(attestedCredData, credIDLen[:]...)
	attestedCredData = append(attestedCredData, d.CredentialID...)
	attestedCredData = append(attestedCredData, coseKey...)

	authData := buildAuthData(rpID, flagUserPresent|flagUserVerified|flagAttestedCredID, 0, attestedCredData)

	return &webauthnpb.CredentialCreationResponse{
		Type:  "public-key",
		RawId: d.CredentialID,
		Response: &webauthnpb.AuthenticatorAttestationResponse{
			ClientDataJson:    clientDataJSON,
			AttestationObject: attestationObjectNone(authData),
		},
	}, nil
}

// SignAssertion answers a login (GetAssertion) challenge.
func (d *SoftWebAuthnDevice) SignAssertion(origin string, assertion *webauthnpb.CredentialAssertion) (*webauthnpb.CredentialAssertionResponse, error) {
	if assertion.GetPublicKey() == nil {
		return nil, fmt.Errorf("assertion challenge has no public key options")
	}
	rpID := assertion.GetPublicKey().GetRpId()
	clientDataJSON := buildClientDataJSON("webauthn.get", assertion.GetPublicKey().GetChallenge(), origin)

	// Real authenticators increment a monotonic counter on every
	// assertion; servers may use it to detect cloned credentials.
	d.counter++
	authData := buildAuthData(rpID, flagUserPresent|flagUserVerified, d.counter, nil)

	clientDataHash := sha256.Sum256(clientDataJSON)
	toSign := make([]byte, 0, len(authData)+len(clientDataHash))
	toSign = append(toSign, authData...)
	toSign = append(toSign, clientDataHash[:]...)
	digest := sha256.Sum256(toSign)

	r, s, err := ecdsa.Sign(rand.Reader, d.Key, digest[:])
	if err != nil {
		return nil, fmt.Errorf("signing assertion: %w", err)
	}
	sig, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return nil, fmt.Errorf("encoding assertion signature: %w", err)
	}

	return &webauthnpb.CredentialAssertionResponse{
		Type:  "public-key",
		RawId: d.CredentialID,
		Response: &webauthnpb.AuthenticatorAssertionResponse{
			ClientDataJson:    clientDataJSON,
			AuthenticatorData: authData,
			Signature:         sig,
		},
	}, nil
}
