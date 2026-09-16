package identity

import (
	"fmt"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	authproto "github.com/gravitational/teleport/api/client/proto"
)

// SoftTOTPDevice generates codes from a shared secret handed out by a
// TOTPRegisterChallenge, the same way an authenticator app would. See
// domain constraint #1: TOTP codes cannot be replayed and are subject to
// the ~30s window, which is why WebAuthn (SoftWebAuthnDevice) is the
// primary login scenario and TOTP is secondary.
type SoftTOTPDevice struct {
	Secret    string
	Digits    otp.Digits
	Algorithm otp.Algorithm
	Period    uint
}

// NewSoftTOTPDeviceFromChallenge builds a device from the server's
// registration challenge, honoring whatever digits/period/algorithm the
// cluster requested rather than assuming Teleport's current defaults
// (6 digits, SHA1, 30s — see lib/auth/usertoken.go newTOTPKey).
func NewSoftTOTPDeviceFromChallenge(ch *authproto.TOTPRegisterChallenge) (*SoftTOTPDevice, error) {
	algo, err := parseTOTPAlgorithm(ch.GetAlgorithm())
	if err != nil {
		return nil, err
	}
	return &SoftTOTPDevice{
		Secret:    ch.GetSecret(),
		Digits:    otp.Digits(ch.GetDigits()),
		Algorithm: algo,
		Period:    uint(ch.GetPeriodSeconds()),
	}, nil
}

func parseTOTPAlgorithm(s string) (otp.Algorithm, error) {
	switch s {
	case "SHA1", "":
		return otp.AlgorithmSHA1, nil
	case "SHA256":
		return otp.AlgorithmSHA256, nil
	case "SHA512":
		return otp.AlgorithmSHA512, nil
	default:
		return 0, fmt.Errorf("unsupported TOTP algorithm %q", s)
	}
}

// Code returns the current TOTP code for t (normally time.Now()).
func (d *SoftTOTPDevice) Code(t time.Time) (string, error) {
	return totp.GenerateCodeCustom(d.Secret, t, totp.ValidateOpts{
		Period:    uint(d.Period),
		Digits:    d.Digits,
		Algorithm: d.Algorithm,
	})
}
