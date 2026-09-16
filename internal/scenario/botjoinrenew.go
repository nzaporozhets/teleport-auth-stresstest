package scenario

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	apiclient "github.com/gravitational/teleport/api/client"
	authproto "github.com/gravitational/teleport/api/client/proto"
	headerv1 "github.com/gravitational/teleport/api/gen/proto/go/teleport/header/v1"
	machineidv1pb "github.com/gravitational/teleport/api/gen/proto/go/teleport/machineid/v1"
	"github.com/gravitational/teleport/api/types"

	"teleport-auth-stress/internal/config"
	"teleport-auth-stress/internal/identity"
)

const (
	// botJoinTokenTTL only needs to outlive the instant between creating
	// the token and consuming it in the same Setup call.
	botJoinTokenTTL = 5 * time.Minute
	// botCertTTL is requested on both the initial join and every
	// renewal. Unlike cert-renewal's plain identities, a token-joined
	// bot's cert is renewable (verified against v17.7.29 source:
	// lib/auth/bot.go's generateCertsBot sets renewable=true for
	// JoinMethodToken specifically), so this is a real, honored TTL on
	// each call, not clamped to a bootstrap value.
	botCertTTL = 30 * time.Minute
)

// botResourceName mirrors Teleport's own naming convention
// (lib/auth/machineid/machineidv1.BotResourceName, v17.7.29: "bot-" +
// botName with spaces replaced by hyphens) — reimplemented locally
// because that package lives outside the api/ module boundary this
// toolkit stays within, the same reason M1 hand-rolled the soft
// WebAuthn/TOTP authenticators instead of importing lib/auth/mocku2f.
func botResourceName(botName string) string {
	return "bot-" + strings.ReplaceAll(botName, " ", "-")
}

// botIdentity is one virtual bot's live state. The client connection is
// deliberately not fixed for the scenario's lifetime — see
// BotJoinRenew's doc comment for why.
type botIdentity struct {
	mu       sync.Mutex
	client   *apiclient.Client
	username string
}

// BotJoinRenew is the "bot-join-renew" scenario: Machine ID join (token
// method) in Setup, followed by a real renewal loop in Execute.
//
// The detail this scenario exists to get right, verified against the
// pinned v17.7.29 source: Teleport enforces a per-bot-instance
// generation counter for token-joined bots specifically
// (lib/auth/bot.go's updateBotInstance: "the counter is now set for all
// join methods, but only enforced for token joins"). Each successful
// renewal increments the counter server-side and embeds the new value
// in the returned certificate; the *next* renewal must authenticate
// using a connection whose certificate carries that same value, or the
// bot is locked as a suspected credential clone
// (tryLockBotDueToGenerationMismatch). A live gRPC connection's client
// certificate can't be swapped in place, so Execute fully reconnects
// with each newly issued certificate before returning — reusing one
// long-lived connection the way cert-renewal does would lock every bot
// after its first renewal. This matches real tbot behavior, which
// reconnects after every renewal for the same reason.
type BotJoinRenew struct {
	identities []*botIdentity
	pool       *identity.KeyPool
	cfg        *config.Config
	next       atomic.Uint64
}

func (s *BotJoinRenew) Name() string { return "bot-join-renew" }

// Setup provisions botCount virtual bots: upserts a Bot resource, mints
// a single-use provisioning token scoped to it (verified: the token
// join method deletes its token immediately after a successful join,
// so each bot needs its own), joins via env.Admin.RegisterUsingToken
// (an authenticated call works fine here — the join RPC authorizes via
// the token itself, not the caller's own mTLS identity; Setup using an
// authenticated connection for this one-time bootstrap matches
// cert-renewal's own precedent of using env.Admin for bootstrap), and
// opens the bot's first connection.
//
// Bot resources created here are not cleaned up by Teardown — the
// Scenario interface's Teardown takes no Env/Admin, so there is no
// admin connection available to delete them with. See
// docs/methodology.md's M7 notes.
func (s *BotJoinRenew) Setup(ctx context.Context, env *Env) error {
	if env.Admin == nil {
		return fmt.Errorf("bot-join-renew Setup requires env.Admin for one-time bot provisioning and join")
	}
	if env.Fixtures == nil {
		return fmt.Errorf("bot-join-renew Setup requires env.Fixtures (run authseed apply first)")
	}
	if env.Config == nil {
		return fmt.Errorf("bot-join-renew Setup requires env.Config")
	}

	pool, err := env.Fixtures.KeyPool()
	if err != nil {
		return fmt.Errorf("loading key pool: %w", err)
	}
	if pool.Size() == 0 {
		return fmt.Errorf("key pool is empty")
	}

	botCount := env.Config.Fixtures.BotCount
	if botCount <= 0 {
		botCount = env.Config.Fixtures.UserCount
	}
	n := botCount
	if pool.Size() < n {
		n = pool.Size()
	}
	if n <= 0 {
		return fmt.Errorf("no bots to provision: fixtures.botCount (or fixtures.userCount as its default) and fixtures.keyPool.size must both be > 0")
	}

	identities := make([]*botIdentity, 0, n)
	for i := 0; i < n; i++ {
		botName := fmt.Sprintf("%sbot-%05d", env.Config.Fixtures.UserPrefix, i)
		tokenName := fmt.Sprintf("%sbot-join-%05d", env.Config.Fixtures.UserPrefix, i)
		kp := pool.At(i)

		if _, err := env.Admin.BotServiceClient().UpsertBot(ctx, &machineidv1pb.UpsertBotRequest{
			Bot: &machineidv1pb.Bot{
				Metadata: &headerv1.Metadata{Name: botName},
				Spec:     &machineidv1pb.BotSpec{Roles: env.Config.Fixtures.Roles},
			},
		}); err != nil {
			return fmt.Errorf("upserting bot %s: %w", botName, err)
		}

		token, err := types.NewProvisionTokenFromSpec(tokenName, time.Now().Add(botJoinTokenTTL), types.ProvisionTokenSpecV2{
			Roles:      []types.SystemRole{types.RoleBot},
			JoinMethod: types.JoinMethodToken,
			BotName:    botName,
		})
		if err != nil {
			return fmt.Errorf("building join token for %s: %w", botName, err)
		}
		if err := env.Admin.UpsertToken(ctx, token); err != nil {
			return fmt.Errorf("upserting join token for %s: %w", botName, err)
		}

		expires := time.Now().Add(botCertTTL)
		certs, err := env.Admin.RegisterUsingToken(ctx, &types.RegisterUsingTokenRequest{
			Token:        tokenName,
			Role:         types.RoleBot,
			PublicSSHKey: kp.SSHPublicKey,
			PublicTLSKey: kp.TLSPublicKey,
			Expires:      &expires,
		})
		if err != nil {
			return fmt.Errorf("joining as bot %s: %w", botName, err)
		}

		clt, err := dialWithFreshCerts(ctx, env.Config, kp, certs)
		if err != nil {
			return fmt.Errorf("connecting as bot %s: %w", botName, err)
		}

		identities = append(identities, &botIdentity{client: clt, username: botResourceName(botName)})
	}

	s.identities = identities
	s.pool = pool
	s.cfg = env.Config
	return nil
}

// Execute renews one bot's certificate, then reconnects using the newly
// issued certificate — see BotJoinRenew's doc comment for why the
// reconnect is not optional. Both steps are measured: a renewal that
// can't be taken up by a fresh connection isn't actually usable for the
// next call, so hiding that cost would understate what a real renewal
// cycle takes.
func (s *BotJoinRenew) Execute(ctx context.Context) (Result, error) {
	idx := s.next.Add(1) - 1
	id := s.identities[idx%uint64(len(s.identities))]
	kp := s.pool.At(int(idx))

	id.mu.Lock()
	defer id.mu.Unlock()

	var phases []Phase

	renewStart := time.Now()
	certs, err := id.client.GenerateUserCerts(ctx, authproto.UserCertsRequest{
		Username:     id.username,
		SSHPublicKey: kp.SSHPublicKey,
		TLSPublicKey: kp.TLSPublicKey,
		Expires:      time.Now().Add(botCertTTL),
	})
	phases = append(phases, Phase{Name: "cert-renew", Duration: time.Since(renewStart).Nanoseconds()})
	if err != nil {
		return Result{Phases: phases, Outcome: ClassifyError(err)}, err
	}

	reconnectStart := time.Now()
	newClient, dialErr := dialWithFreshCerts(ctx, s.cfg, kp, certs)
	phases = append(phases, Phase{Name: "reconnect", Duration: time.Since(reconnectStart).Nanoseconds()})
	if dialErr != nil {
		// The renewal itself succeeded but the connection to use it
		// couldn't be established; id.client still holds the
		// now-superseded certificate. A subsequent renewal on it will
		// likely be rejected as a generation mismatch (see doc
		// comment) — a known, narrow edge case (a dial failing in the
		// instant right after a successful renewal), not specially
		// recovered from here.
		return Result{Phases: phases, Outcome: ClassifyError(dialErr)}, dialErr
	}

	old := id.client
	id.client = newClient
	old.Close() //nolint:errcheck

	return Result{
		Phases:  phases,
		Outcome: Success,
		Bytes:   int64(len(certs.TLS)),
	}, nil
}

func (s *BotJoinRenew) Teardown(ctx context.Context) error {
	var firstErr error
	for _, id := range s.identities {
		id.mu.Lock()
		if err := id.client.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
		id.mu.Unlock()
	}
	return firstErr
}

// dialWithFreshCerts builds TLS credentials from a freshly issued cert
// bundle and opens a new client — used both for the initial join
// (Setup) and for every renewal (Execute), since a live gRPC
// connection's client certificate cannot be swapped in place.
// certs.TLSCACerts is populated on every call (verified against
// source: lib/auth's shared generateUserCert path "always include[s]
// specified CA" regardless of whether this is an initial bot join or a
// later renewal), so this never depends on caching CA material from an
// earlier call.
func dialWithFreshCerts(ctx context.Context, cfg *config.Config, kp *identity.KeyPair, certs *authproto.Certs) (*apiclient.Client, error) {
	keyPEM, err := kp.PrivateKeyPEM()
	if err != nil {
		return nil, fmt.Errorf("encoding private key: %w", err)
	}
	creds, err := apiclient.KeyPair(certs.TLS, keyPEM, bytes.Join(certs.TLSCACerts, nil))
	if err != nil {
		return nil, fmt.Errorf("building credentials: %w", err)
	}
	return identity.NewClient(ctx, cfg, creds)
}
