package identity

import (
	"testing"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"

	authproto "github.com/gravitational/teleport/api/client/proto"
)

func TestSoftTOTPDevice_CodeValidatesWithRealLibrary(t *testing.T) {
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      "test-cluster",
		AccountName: "stress-00001",
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("totp.Generate: %v", err)
	}

	challenge := &authproto.TOTPRegisterChallenge{
		Secret:        key.Secret(),
		Issuer:        key.Issuer(),
		PeriodSeconds: 30,
		Algorithm:     "SHA1",
		Digits:        6,
		Account:       key.AccountName(),
		ID:            "test-token",
	}

	device, err := NewSoftTOTPDeviceFromChallenge(challenge)
	if err != nil {
		t.Fatalf("NewSoftTOTPDeviceFromChallenge: %v", err)
	}

	now := time.Now()
	code, err := device.Code(now)
	if err != nil {
		t.Fatalf("Code: %v", err)
	}

	valid, err := totp.ValidateCustom(code, key.Secret(), now, totp.ValidateOpts{
		Period:    30,
		Digits:    otp.DigitsSix,
		Algorithm: otp.AlgorithmSHA1,
	})
	if err != nil {
		t.Fatalf("ValidateCustom: %v", err)
	}
	if !valid {
		t.Fatal("real otp library rejected our soft TOTP device's code")
	}
}

func TestSoftTOTPDevice_UnsupportedAlgorithm(t *testing.T) {
	_, err := NewSoftTOTPDeviceFromChallenge(&authproto.TOTPRegisterChallenge{Algorithm: "SHA999"})
	if err == nil {
		t.Fatal("expected error for unsupported algorithm")
	}
}
