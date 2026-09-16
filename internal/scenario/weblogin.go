package scenario

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/gravitational/trace"
)

// encodeBase64URL is the encoding the WebAuthn spec uses for the
// PublicKeyCredential.id string field (as opposed to rawId, which is
// protocol.URLEncodedBase64 and encodes itself the same way, but id is a
// plain string field we have to encode ourselves).
func encodeBase64URL(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

// The proxy web API's login endpoints (POST /webapi/mfa/login/begin,
// POST /webapi/mfa/login/finish) are HTTP/JSON, and their Go wire types
// (client.MFAChallengeRequest, client.AuthenticateSSHUserRequest,
// authclient.SSHLoginResponse, etc.) live in lib/client and
// lib/auth/authclient — outside the api/ module boundary this toolkit
// stays within (see docs/methodology.md). These are local, minimal
// re-declarations of just the fields we send/read, with the exact same
// JSON tags as the real types (verified against the pinned v17.7.29
// source), not full copies of Teleport's structs.
//
// One genuine wire-format subtlety: loginBeginResponse's Challenge field
// is a plain []byte (Go's encoding/json default: base64.StdEncoding,
// padded) — NOT protocol.URLEncodedBase64 (base64.RawURLEncoding). The
// WebAuthn-spec-level clientDataJSON "challenge" field is a *different*
// base64url string built locally by SoftWebAuthnDevice from the decoded
// raw bytes. Getting the wire encoding right here (plain []byte) is what
// makes json.Unmarshal decode it correctly without any manual handling.

type loginBeginRequest struct {
	User string `json:"user"`
	Pass string `json:"pass"`
}

type loginBeginResponse struct {
	WebauthnChallenge *credentialAssertion `json:"webauthn_challenge"`
	TOTPChallenge     bool                 `json:"totp_challenge"`
}

type credentialAssertion struct {
	Response publicKeyCredentialRequestOptions `json:"publicKey"`
}

type publicKeyCredentialRequestOptions struct {
	Challenge      []byte `json:"challenge"`
	RelyingPartyID string `json:"rpId,omitempty"`
}

// credentialAssertionResponseWire mirrors lib/auth/webauthntypes'
// CredentialAssertionResponse, whose byte fields ARE
// protocol.URLEncodedBase64 (base64.RawURLEncoding) — reusing that type
// directly from the already-dependency go-webauthn/webauthn/protocol
// package guarantees the same encoding rather than us re-deriving it.
type credentialAssertionResponseWire struct {
	ID                string                     `json:"id"`
	Type              string                     `json:"type"`
	RawID             protocol.URLEncodedBase64  `json:"rawId"`
	AssertionResponse authenticatorAssertionWire `json:"response"`
}

type authenticatorAssertionWire struct {
	ClientDataJSON    protocol.URLEncodedBase64 `json:"clientDataJSON"`
	AuthenticatorData protocol.URLEncodedBase64 `json:"authenticatorData"`
	Signature         protocol.URLEncodedBase64 `json:"signature"`
}

type loginFinishRequest struct {
	User                      string                           `json:"user"`
	Password                  string                           `json:"password"`
	WebauthnChallengeResponse *credentialAssertionResponseWire `json:"webauthn_challenge_response,omitempty"`
	TOTPCode                  string                           `json:"totp_code,omitempty"`
	SSHPubKey                 []byte                           `json:"ssh_pub_key,omitempty"`
	TLSPubKey                 []byte                           `json:"tls_pub_key,omitempty"`
	TTL                       time.Duration                    `json:"ttl"`
}

type sshLoginResponse struct {
	Username    string         `json:"username"`
	Cert        []byte         `json:"cert"`
	TLSCert     []byte         `json:"tls_cert"`
	HostSigners []trustedCerts `json:"host_signers"`
	MFAToken    string         `json:"mfa_token"`
}

type trustedCerts struct {
	ClusterName     string   `json:"domain_name"`
	AuthorizedKeys  [][]byte `json:"checking_keys"`
	TLSCertificates [][]byte `json:"tls_certs"`
}

// postJSON POSTs reqBody as JSON to url and decodes a 2xx response into
// respBody (if non-nil). A non-2xx response is converted back into the
// same github.com/gravitational/trace error type the server's
// trace.WriteError produced, via trace.ReadError — see ClassifyError,
// which already knows how to route these.
func postJSON(ctx context.Context, client *http.Client, url string, reqBody, respBody any) error {
	buf, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("marshalling request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("building request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return trace.ReadError(resp.StatusCode, body)
	}
	if respBody != nil {
		if err := json.Unmarshal(body, respBody); err != nil {
			return fmt.Errorf("parsing response: %w", err)
		}
	}
	return nil
}
