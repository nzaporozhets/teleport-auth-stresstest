package config

import "fmt"

// CheckLiveClusterName enforces the non-negotiable guardrail: refuse to run
// unless the cluster actually connected to matches
// target.guardrail.requireClusterName. Call this after connecting, in
// addition to (not instead of) Validate, which only checks the config file
// for internal self-consistency.
func (c *Config) CheckLiveClusterName(liveClusterName string) error {
	if liveClusterName != c.Target.Guardrail.RequireClusterName {
		return fmt.Errorf("refusing to run: connected cluster %q does not match target.guardrail.requireClusterName %q", liveClusterName, c.Target.Guardrail.RequireClusterName)
	}
	return nil
}
