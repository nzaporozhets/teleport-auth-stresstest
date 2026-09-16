package identity

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	authproto "github.com/gravitational/teleport/api/client/proto"
	"github.com/gravitational/teleport/api/types"

	"teleport-auth-stress/internal/config"
)

// userTokenTypeResetPassword mirrors
// lib/auth/authclient.UserTokenTypeResetPassword (Teleport v17.7.29,
// lib/auth/authclient/clt.go:439), which lives outside the api/ module
// boundary and isn't importable from here.
const userTokenTypeResetPassword = "password"

const resetTokenTTL = time.Hour

// ApplyResult summarizes what ApplyFixtures did, for the CLI to print.
type ApplyResult struct {
	UsersCreated int
	KeyPoolSize  int
	StatePath    string
}

// ApplyFixtures creates (or converges) fixtures.roles and
// fixtures.userCount local users with the requested second factor, plus a
// fresh keypair pool, then writes everything to fixtures.statePath.
// Every created/updated user's name is prefixed with fixtures.userPrefix
// (see TeardownFixtures, which relies on that invariant to scope
// deletes). Re-running apply is safe: UpsertUser/UpsertRole converge the
// resource, though the MFA-registration ceremony always re-runs and
// therefore rotates each user's password and device on every apply (see
// docs/methodology.md).
func ApplyFixtures(ctx context.Context, cfg *config.Config, admin *AdminClient) (*ApplyResult, error) {
	clusterName, _, err := admin.CheckLiveClusterName(ctx, cfg)
	if err != nil {
		return nil, err
	}

	for _, roleName := range cfg.Fixtures.Roles {
		if err := upsertRole(ctx, admin, roleName); err != nil {
			return nil, fmt.Errorf("role %s: %w", roleName, err)
		}
	}

	users := make([]UserFixture, 0, cfg.Fixtures.UserCount)
	for i := 0; i < cfg.Fixtures.UserCount; i++ {
		username := fmt.Sprintf("%s%05d", cfg.Fixtures.UserPrefix, i)
		uf, err := applyUser(ctx, admin, cfg, username)
		if err != nil {
			return nil, fmt.Errorf("user %s: %w", username, err)
		}
		users = append(users, *uf)
	}

	pool, err := GenerateKeyPool(cfg.Fixtures.KeyPool.Algorithm, cfg.Fixtures.KeyPool.Size)
	if err != nil {
		return nil, fmt.Errorf("generating key pool: %w", err)
	}
	pemKeys := make([][]byte, pool.Size())
	for i, kp := range pool.Pairs() {
		pemBytes, err := marshalPrivateKeyPEM(kp.Private)
		if err != nil {
			return nil, fmt.Errorf("encoding key pool entry %d: %w", i, err)
		}
		pemKeys[i] = pemBytes
	}

	state := &FixtureState{
		ClusterName: clusterName,
		GeneratedAt: time.Now().UTC(),
		UserPrefix:  cfg.Fixtures.UserPrefix,
		Users:       users,
		KeyPoolState: KeyPoolFixture{
			Algorithm:      cfg.Fixtures.KeyPool.Algorithm,
			PrivateKeyPEMs: pemKeys,
		},
	}
	if err := SaveFixtureState(cfg.Fixtures.StatePath, state); err != nil {
		return nil, err
	}

	return &ApplyResult{UsersCreated: len(users), KeyPoolSize: pool.Size(), StatePath: cfg.Fixtures.StatePath}, nil
}

// TeardownFixtures deletes every user whose name matches
// fixtures.userPrefix and no others: the client-side filter below is the
// only thing standing between this call and an unscoped delete, so it
// must run before, not as part of, any per-user delete call.
func TeardownFixtures(ctx context.Context, cfg *config.Config, admin *AdminClient) (int, error) {
	if _, _, err := admin.CheckLiveClusterName(ctx, cfg); err != nil {
		return 0, err
	}

	all, err := admin.GetUsers(ctx, false)
	if err != nil {
		return 0, fmt.Errorf("listing users: %w", err)
	}

	deleted := 0
	for _, u := range all {
		name := u.GetName()
		if !strings.HasPrefix(name, cfg.Fixtures.UserPrefix) {
			continue
		}
		if err := admin.DeleteUser(ctx, name); err != nil {
			return deleted, fmt.Errorf("deleting user %s: %w", name, err)
		}
		deleted++
	}
	return deleted, nil
}

func upsertRole(ctx context.Context, admin *AdminClient, name string) error {
	role, err := types.NewRole(name, types.RoleSpecV6{})
	if err != nil {
		return fmt.Errorf("constructing role: %w", err)
	}
	if _, err := admin.UpsertRole(ctx, role); err != nil {
		return fmt.Errorf("upserting role: %w", err)
	}
	return nil
}

func applyUser(ctx context.Context, admin *AdminClient, cfg *config.Config, username string) (*UserFixture, error) {
	user, err := types.NewUser(username)
	if err != nil {
		return nil, fmt.Errorf("constructing user: %w", err)
	}
	user.SetRoles(cfg.Fixtures.Roles)
	if _, err := admin.UpsertUser(ctx, user); err != nil {
		return nil, fmt.Errorf("upserting user: %w", err)
	}

	password, err := randomPassword()
	if err != nil {
		return nil, err
	}
	uf := &UserFixture{Username: username, Password: password, SecondFactor: cfg.Fixtures.SecondFactor}

	token, err := admin.CreateResetPasswordToken(ctx, &authproto.CreateResetPasswordTokenRequest{
		Name: username,
		Type: userTokenTypeResetPassword,
		TTL:  authproto.Duration(resetTokenTTL),
	})
	if err != nil {
		return nil, fmt.Errorf("creating reset token: %w", err)
	}
	tokenID := token.GetName()

	var mfaResp *authproto.MFARegisterResponse
	var deviceName string
	switch cfg.Fixtures.SecondFactor {
	case config.SecondFactorNone:
		// No device to register; password only.
	case config.SecondFactorWebAuthn:
		deviceName = "stress-webauthn"
		mfaResp, err = registerWebAuthnDevice(ctx, admin, cfg, tokenID, uf)
	case config.SecondFactorTOTP:
		deviceName = "stress-totp"
		mfaResp, err = registerTOTPDevice(ctx, admin, tokenID, uf)
	default:
		return nil, fmt.Errorf("unsupported second factor %q", cfg.Fixtures.SecondFactor)
	}
	if err != nil {
		return nil, err
	}

	if _, err := admin.ChangeUserAuthentication(ctx, &authproto.ChangeUserAuthenticationRequest{
		TokenID:                tokenID,
		NewPassword:            []byte(password),
		NewMFARegisterResponse: mfaResp,
		NewDeviceName:          deviceName,
	}); err != nil {
		return nil, fmt.Errorf("setting password/device: %w", err)
	}

	return uf, nil
}

func registerWebAuthnDevice(ctx context.Context, admin *AdminClient, cfg *config.Config, tokenID string, uf *UserFixture) (*authproto.MFARegisterResponse, error) {
	challenge, err := admin.CreateRegisterChallenge(ctx, &authproto.CreateRegisterChallengeRequest{
		TokenID:    tokenID,
		DeviceType: authproto.DeviceType_DEVICE_TYPE_WEBAUTHN,
	})
	if err != nil {
		return nil, fmt.Errorf("creating webauthn register challenge: %w", err)
	}

	device, err := NewSoftWebAuthnDevice()
	if err != nil {
		return nil, err
	}

	resp, err := device.SignRegistration(OriginFromProxyAddr(cfg.Target.ProxyAddr), challenge.GetWebauthn())
	if err != nil {
		return nil, fmt.Errorf("signing webauthn registration: %w", err)
	}

	keyPEM, err := marshalPrivateKeyPEM(device.Key)
	if err != nil {
		return nil, fmt.Errorf("encoding webauthn device key: %w", err)
	}
	uf.WebAuthnCredentialID = device.CredentialID
	uf.WebAuthnPrivateKeyPEM = keyPEM

	return &authproto.MFARegisterResponse{Response: &authproto.MFARegisterResponse_Webauthn{Webauthn: resp}}, nil
}

func registerTOTPDevice(ctx context.Context, admin *AdminClient, tokenID string, uf *UserFixture) (*authproto.MFARegisterResponse, error) {
	challenge, err := admin.CreateRegisterChallenge(ctx, &authproto.CreateRegisterChallengeRequest{
		TokenID:    tokenID,
		DeviceType: authproto.DeviceType_DEVICE_TYPE_TOTP,
	})
	if err != nil {
		return nil, fmt.Errorf("creating totp register challenge: %w", err)
	}
	totpChallenge := challenge.GetTOTP()

	device, err := NewSoftTOTPDeviceFromChallenge(totpChallenge)
	if err != nil {
		return nil, err
	}
	code, err := device.Code(time.Now())
	if err != nil {
		return nil, fmt.Errorf("generating totp code: %w", err)
	}

	uf.TOTPSecret = totpChallenge.GetSecret()
	uf.TOTPDigits = totpChallenge.GetDigits()
	uf.TOTPAlgorithm = totpChallenge.GetAlgorithm()
	uf.TOTPPeriod = totpChallenge.GetPeriodSeconds()

	return &authproto.MFARegisterResponse{
		Response: &authproto.MFARegisterResponse_TOTP{
			TOTP: &authproto.TOTPRegisterResponse{Code: code, ID: totpChallenge.GetID()},
		},
	}, nil
}

// OriginFromProxyAddr builds the WebAuthn origin the soft authenticator
// signs into clientDataJSON. Teleport validates this against the
// proxy's configured public address; the default HTTPS port is omitted,
// matching what a real browser would send. Exported because both
// authseed's registration ceremony and the local-login-webauthn
// scenario's assertion ceremony need the same origin string.
func OriginFromProxyAddr(addr string) string {
	host := addr
	if i := strings.LastIndex(addr, ":"); i != -1 && addr[i+1:] == "443" {
		host = addr[:i]
	}
	return "https://" + host
}

func randomPassword() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generating password: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
