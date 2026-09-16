package config

import (
	"fmt"
	"strings"
)

// ValidationError aggregates every problem found in a Config so an operator
// sees all of them at once instead of fixing one field per run.
type ValidationError struct {
	Errors []string
}

func (v *ValidationError) Error() string {
	return fmt.Sprintf("config invalid (%d error(s)):\n  - %s", len(v.Errors), strings.Join(v.Errors, "\n  - "))
}

func (v *ValidationError) add(format string, args ...any) {
	v.Errors = append(v.Errors, fmt.Sprintf(format, args...))
}

// Validate checks schema-level and guardrail-level correctness. It does not
// contact the cluster: guardrail.requireClusterName is checked for
// self-consistency against target.cluster only. The live cluster-name check
// against the connected cluster happens at run time in addition to this.
func (c *Config) Validate() error {
	v := &ValidationError{}

	c.validateTarget(v)
	c.validateIdentity(v)
	c.validateFixtures(v)
	c.validateLoad(v)
	c.validateObservability(v)
	c.validateReport(v)

	if len(v.Errors) > 0 {
		return v
	}
	return nil
}

func (c *Config) validateTarget(v *ValidationError) {
	if c.Target.ProxyAddr == "" {
		v.add("target.proxyAddr is required")
	}
	if c.Target.Cluster == "" {
		v.add("target.cluster is required")
	}

	if c.Target.Guardrail.RequireClusterName == "" {
		v.add("target.guardrail.requireClusterName is required (this is the non-negotiable cluster-name guardrail; see instructions.md Guardrails)")
	} else if c.Target.Cluster != "" && c.Target.Guardrail.RequireClusterName != c.Target.Cluster {
		v.add("target.guardrail.requireClusterName (%q) does not match target.cluster (%q): refusing to accept a config whose safety gate targets a different cluster than the one it's configured against", c.Target.Guardrail.RequireClusterName, c.Target.Cluster)
	}

	if c.Target.Guardrail.ConfirmPhrase != RequiredConfirmPhrase {
		v.add("target.guardrail.confirmPhrase must be exactly %q, got %q", RequiredConfirmPhrase, c.Target.Guardrail.ConfirmPhrase)
	}
}

func (c *Config) validateIdentity(v *ValidationError) {
	if c.Identity.AdminIdentityFile == "" {
		v.add("identity.adminIdentityFile is required (seeding only; never referenced from the load path)")
	}
}

func (c *Config) validateFixtures(v *ValidationError) {
	if c.Fixtures.UserCount <= 0 {
		v.add("fixtures.userCount must be > 0")
	}
	if c.Fixtures.UserPrefix == "" {
		v.add("fixtures.userPrefix is required: authseed scopes every create/delete to this prefix and must never operate unscoped")
	}
	if c.Fixtures.StatePath == "" {
		v.add("fixtures.statePath is required: authseed apply writes seeded credentials here for authload to read")
	}
	if len(c.Fixtures.Roles) == 0 {
		v.add("fixtures.roles must list at least one role")
	}
	switch c.Fixtures.SecondFactor {
	case SecondFactorNone, SecondFactorTOTP, SecondFactorWebAuthn:
	default:
		v.add("fixtures.secondFactor must be one of none|totp|webauthn, got %q", c.Fixtures.SecondFactor)
	}

	if c.Fixtures.KeyPool.Size <= 0 {
		v.add("fixtures.keyPool.size must be > 0 (keypairs are pre-generated; none are generated in the hot path)")
	}
	switch c.Fixtures.KeyPool.Algorithm {
	case KeyAlgorithmECDSA, KeyAlgorithmEd25519, KeyAlgorithmRSA2048:
	default:
		v.add("fixtures.keyPool.algorithm must be one of ecdsa|ed25519|rsa2048, got %q", c.Fixtures.KeyPool.Algorithm)
	}
}

func (c *Config) validateLoad(v *ValidationError) {
	if !validScenarios[c.Load.Scenario] {
		v.add("load.scenario %q is not a known scenario", c.Load.Scenario)
	}
	switch c.Load.Model {
	case LoadModelOpen, LoadModelClosed:
	default:
		v.add("load.model must be one of open|closed, got %q", c.Load.Model)
	}
	switch c.Load.Arrival {
	case ArrivalPoisson, ArrivalUniform:
	default:
		v.add("load.arrival must be one of poisson|uniform, got %q", c.Load.Arrival)
	}

	r := c.Load.Ramp
	if r.StartRPS <= 0 {
		v.add("load.ramp.startRPS must be > 0")
	}
	if r.StepRPS <= 0 {
		v.add("load.ramp.stepRPS must be > 0")
	}
	if r.StepDuration <= 0 {
		v.add("load.ramp.stepDuration must be > 0")
	}
	if r.Warmup < 0 {
		v.add("load.ramp.warmup must be >= 0")
	}
	if r.Settle < 0 {
		v.add("load.ramp.settle must be >= 0")
	}
	if r.MaxRPS <= 0 {
		v.add("load.ramp.maxRPS must be > 0")
	}
	if r.StartRPS > 0 && r.MaxRPS > 0 && r.MaxRPS < r.StartRPS {
		v.add("load.ramp.maxRPS (%v) must be >= load.ramp.startRPS (%v)", r.MaxRPS, r.StartRPS)
	}

	a := c.Load.Abort
	if a.P99LatencyMs <= 0 {
		v.add("load.abort.p99LatencyMs must be > 0")
	}
	if a.ErrorRatePct < 0 || a.ErrorRatePct > 100 {
		v.add("load.abort.errorRatePct must be within [0, 100], got %v", a.ErrorRatePct)
	}
	if a.ThroughputDeficitPct < 0 || a.ThroughputDeficitPct > 100 {
		v.add("load.abort.throughputDeficitPct must be within [0, 100], got %v", a.ThroughputDeficitPct)
	}
	if a.ConsecutiveBadSteps < 1 {
		v.add("load.abort.consecutiveBadSteps must be >= 1")
	}
}

func (c *Config) validateObservability(v *ValidationError) {
	if c.Observability.Listen == "" {
		v.add("observability.listen is required")
	}

	names := make(map[string]bool, len(c.Observability.Scrape))
	for i, s := range c.Observability.Scrape {
		if s.Name == "" {
			v.add("observability.scrape[%d].name is required", i)
		}
		if s.URL == "" {
			v.add("observability.scrape[%d].url is required", i)
		}
		if s.Interval <= 0 {
			v.add("observability.scrape[%d].interval must be > 0", i)
		}
		names[s.Name] = true
	}

	if c.Observability.Pprof.Enabled {
		for _, t := range c.Observability.Pprof.Targets {
			if !names[t] {
				v.add("observability.pprof.targets references %q which is not in observability.scrape", t)
			}
		}
	}
}

func (c *Config) validateReport(v *ValidationError) {
	if c.Report.OutputDir == "" {
		v.add("report.outputDir is required")
	}
	if len(c.Report.Formats) == 0 {
		v.add("report.formats must list at least one format")
	}
	for i, f := range c.Report.Formats {
		switch f {
		case ReportFormatJSON, ReportFormatMarkdown:
		default:
			v.add("report.formats[%d] must be one of json|markdown, got %q", i, f)
		}
	}
}
