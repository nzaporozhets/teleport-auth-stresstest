package identity

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"

	webauthnpb "github.com/gravitational/teleport/api/types/webauthn"
)

// These tests verify our hand-rolled soft WebAuthn authenticator's output
// against github.com/go-webauthn/webauthn — the same library Teleport's
// server uses to verify real WebAuthn responses (lib/auth/auth.go, see
// go.mod: github.com/go-webauthn/webauthn v0.11.2). That's a much
// stronger check than round-tripping against our own encoder.

const testRPID = "example.com"
const testOrigin = "https://example.com"

func randomChallenge(t *testing.T) []byte {
	t.Helper()
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("generating challenge: %v", err)
	}
	return b
}

func creationJSON(resp *webauthnpb.CredentialCreationResponse) ([]byte, error) {
	return json.Marshal(map[string]any{
		"id":    base64.RawURLEncoding.EncodeToString(resp.RawId),
		"rawId": base64.RawURLEncoding.EncodeToString(resp.RawId),
		"type":  resp.Type,
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(resp.Response.ClientDataJson),
			"attestationObject": base64.RawURLEncoding.EncodeToString(resp.Response.AttestationObject),
		},
	})
}

func assertionJSON(resp *webauthnpb.CredentialAssertionResponse) ([]byte, error) {
	return json.Marshal(map[string]any{
		"id":    base64.RawURLEncoding.EncodeToString(resp.RawId),
		"rawId": base64.RawURLEncoding.EncodeToString(resp.RawId),
		"type":  resp.Type,
		"response": map[string]any{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(resp.Response.ClientDataJson),
			"authenticatorData": base64.RawURLEncoding.EncodeToString(resp.Response.AuthenticatorData),
			"signature":         base64.RawURLEncoding.EncodeToString(resp.Response.Signature),
		},
	})
}

func TestSoftWebAuthnDevice_RegistrationVerifiesWithRealLibrary(t *testing.T) {
	challenge := randomChallenge(t)
	cc := &webauthnpb.CredentialCreation{
		PublicKey: &webauthnpb.PublicKeyCredentialCreationOptions{
			Challenge: challenge,
			Rp:        &webauthnpb.RelyingPartyEntity{Id: testRPID, Name: "Test RP"},
		},
	}

	device, err := NewSoftWebAuthnDevice()
	if err != nil {
		t.Fatalf("NewSoftWebAuthnDevice: %v", err)
	}

	resp, err := device.SignRegistration(testOrigin, cc)
	if err != nil {
		t.Fatalf("SignRegistration: %v", err)
	}

	body, err := creationJSON(resp)
	if err != nil {
		t.Fatalf("marshalling response: %v", err)
	}

	pcc, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil {
		t.Fatalf("ParseCredentialCreationResponseBytes: %v", err)
	}

	if _, err := pcc.Verify(
		base64.RawURLEncoding.EncodeToString(challenge),
		false, // verifyUser (we don't need UV flag semantics checked here)
		testRPID,
		[]string{testOrigin},
		nil,
		protocol.TopOriginIgnoreVerificationMode,
		nil,
	); err != nil {
		t.Fatalf("real WebAuthn library rejected our registration response: %v", err)
	}
}

func TestSoftWebAuthnDevice_AssertionVerifiesWithRealLibrary(t *testing.T) {
	regChallenge := randomChallenge(t)
	cc := &webauthnpb.CredentialCreation{
		PublicKey: &webauthnpb.PublicKeyCredentialCreationOptions{
			Challenge: regChallenge,
			Rp:        &webauthnpb.RelyingPartyEntity{Id: testRPID, Name: "Test RP"},
		},
	}
	device, err := NewSoftWebAuthnDevice()
	if err != nil {
		t.Fatalf("NewSoftWebAuthnDevice: %v", err)
	}
	regResp, err := device.SignRegistration(testOrigin, cc)
	if err != nil {
		t.Fatalf("SignRegistration: %v", err)
	}
	regBody, err := creationJSON(regResp)
	if err != nil {
		t.Fatalf("marshalling registration response: %v", err)
	}
	pcc, err := protocol.ParseCredentialCreationResponseBytes(regBody)
	if err != nil {
		t.Fatalf("ParseCredentialCreationResponseBytes: %v", err)
	}
	if _, err := pcc.Verify(
		base64.RawURLEncoding.EncodeToString(regChallenge), false, testRPID,
		[]string{testOrigin}, nil, protocol.TopOriginIgnoreVerificationMode, nil,
	); err != nil {
		t.Fatalf("registration did not verify: %v", err)
	}
	credentialPublicKey := pcc.Response.AttestationObject.AuthData.AttData.CredentialPublicKey

	loginChallenge := randomChallenge(t)
	assertion := &webauthnpb.CredentialAssertion{
		PublicKey: &webauthnpb.PublicKeyCredentialRequestOptions{
			Challenge: loginChallenge,
			RpId:      testRPID,
		},
	}
	assertResp, err := device.SignAssertion(testOrigin, assertion)
	if err != nil {
		t.Fatalf("SignAssertion: %v", err)
	}
	assertBody, err := assertionJSON(assertResp)
	if err != nil {
		t.Fatalf("marshalling assertion response: %v", err)
	}

	pca, err := protocol.ParseCredentialRequestResponseBytes(assertBody)
	if err != nil {
		t.Fatalf("ParseCredentialRequestResponseBytes: %v", err)
	}

	if err := pca.Verify(
		base64.RawURLEncoding.EncodeToString(loginChallenge),
		testRPID,
		[]string{testOrigin},
		nil,
		protocol.TopOriginIgnoreVerificationMode,
		"",
		false,
		credentialPublicKey,
	); err != nil {
		t.Fatalf("real WebAuthn library rejected our assertion response: %v", err)
	}
}
