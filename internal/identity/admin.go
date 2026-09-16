package identity

import (
	"context"
	"fmt"

	apiclient "github.com/gravitational/teleport/api/client"

	"teleport-auth-stress/internal/config"
)

// AdminClient wraps the Teleport client used for fixture provisioning
// (authseed) only. Per the guardrails, the admin identity must never be
// referenced from any code path inside a Scenario's Execute — only from
// authseed and from a scenario's one-time Setup where it hands off
// already-issued, scenario-scoped credentials.
type AdminClient struct {
	*apiclient.Client
}

// NewAdminClient dials the target cluster using the admin identity file.
func NewAdminClient(ctx context.Context, cfg *config.Config) (*AdminClient, error) {
	clt, err := NewClient(ctx, cfg, apiclient.LoadIdentityFile(cfg.Identity.AdminIdentityFile))
	if err != nil {
		return nil, err
	}
	return &AdminClient{Client: clt}, nil
}

// NewClient dials the target cluster with the given credentials. It
// prefers dialing the proxy with ALPN SNI routing (so the harness can run
// from outside the cluster via the public proxy address, per
// instructions.md's "Assumptions" table) and falls back to a direct auth
// address if target.authAddr is set. Used both for the admin client
// (authseed) and for the per-identity clients a scenario's Setup builds
// from bootstrap-issued credentials (never from Execute).
func NewClient(ctx context.Context, cfg *config.Config, creds apiclient.Credentials) (*apiclient.Client, error) {
	addr := cfg.Target.AuthAddr
	clientCfg := apiclient.Config{Credentials: []apiclient.Credentials{creds}}
	if addr == "" {
		addr = cfg.Target.ProxyAddr
		clientCfg.ALPNSNIAuthDialClusterName = cfg.Target.Cluster
	}
	if addr == "" {
		return nil, fmt.Errorf("neither target.authAddr nor target.proxyAddr is set")
	}
	clientCfg.Addrs = []string{addr}

	clt, err := apiclient.New(ctx, clientCfg)
	if err != nil {
		return nil, fmt.Errorf("connecting to %s: %w", addr, err)
	}
	return clt, nil
}

// CheckLiveClusterName enforces the non-negotiable cluster-name guardrail
// against the cluster this client is actually connected to, not just the
// config file's self-consistency (see config.Config.CheckLiveClusterName).
func (c *AdminClient) CheckLiveClusterName(ctx context.Context, cfg *config.Config) (clusterName, serverVersion string, err error) {
	resp, err := c.Ping(ctx)
	if err != nil {
		return "", "", fmt.Errorf("pinging cluster: %w", err)
	}
	if err := cfg.CheckLiveClusterName(resp.ClusterName); err != nil {
		return "", "", err
	}
	return resp.ClusterName, resp.ServerVersion, nil
}
