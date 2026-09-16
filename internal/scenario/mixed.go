package scenario

import (
	"context"
	"fmt"
	"math/rand/v2"

	"teleport-auth-stress/internal/config"
)

type mixedChild struct {
	name     config.ScenarioName
	scenario Scenario
}

// Mixed is the "mixed" scenario: a weighted blend of other scenarios,
// weights from config.load.mixed.weights (instructions.md's scenario
// table: "Weighted blend of the above, weights from config"). It is
// itself just another Scenario — the driver, collector, and ramp
// controller have no idea Mixed is composing others, which is exactly
// M7's "no scenario-specific branching in driver or reporter"
// acceptance criterion.
type Mixed struct {
	children []mixedChild
	picker   weightedPicker
}

func (s *Mixed) Name() string { return "mixed" }

// newSubScenario is a small, scenario-package-local factory for the
// scenarios Mixed can blend. It's deliberately separate from
// cmd/authload/main.go's own newScenario: that one is CLI wiring for
// picking the single scenario `authload run` drives; this one lets
// Mixed build its own children from config without cmd/authload
// needing to know Mixed's internals (and without an import cycle, since
// cmd/authload already imports this package, not the reverse).
func newSubScenario(name config.ScenarioName) (Scenario, error) {
	switch name {
	case config.ScenarioCertRenewal:
		return &CertRenewal{}, nil
	case config.ScenarioLocalLoginWebAuthn:
		return &LocalLoginWebAuthn{}, nil
	case config.ScenarioLocalLoginTOTP:
		return &LocalLoginTOTP{}, nil
	case config.ScenarioBotJoinRenew:
		return &BotJoinRenew{}, nil
	case config.ScenarioRouteCertIssuance:
		return &RouteCertIssuance{}, nil
	default:
		return nil, fmt.Errorf("mixed: %q is not a scenario mixed can blend", name)
	}
}

// Setup builds and sets up every weighted child scenario against the
// same Env. config.Validate already rejects unknown/nested-mixed
// weight keys and non-positive weights when a config goes through
// LoadAndValidate (internal/config/validate.go's validateMixed) — the
// checks repeated here are for callers (tests, or future callers) that
// construct a Config directly and skip that validation.
func (s *Mixed) Setup(ctx context.Context, env *Env) error {
	if env.Config == nil {
		return fmt.Errorf("mixed Setup requires env.Config")
	}
	weights := env.Config.Load.Mixed.Weights
	if len(weights) < 2 {
		return fmt.Errorf("mixed requires load.mixed.weights to list at least two scenarios")
	}

	children := make([]mixedChild, 0, len(weights))
	weightValues := make([]float64, 0, len(weights))
	for name, weight := range weights {
		if weight <= 0 {
			return fmt.Errorf("mixed: load.mixed.weights[%q] must be > 0, got %v", name, weight)
		}
		sub, err := newSubScenario(name)
		if err != nil {
			return err
		}
		if err := sub.Setup(ctx, env); err != nil {
			return fmt.Errorf("mixed: setting up %q: %w", name, err)
		}
		children = append(children, mixedChild{name: name, scenario: sub})
		weightValues = append(weightValues, weight)
	}

	s.children = children
	s.picker = newWeightedPicker(weightValues)
	return nil
}

// Execute picks one child scenario via weighted random selection and
// delegates to it — over many calls, each child's share of calls
// converges to weight/totalWeight, matching "weighted blend... weights
// from config" literally. The Result returned is exactly whatever the
// chosen child produced; Mixed doesn't tag which child ran (Result has
// no field for it, and adding one for a single scenario would be
// scenario-specific branching in the report, which is exactly what M7
// prohibits).
func (s *Mixed) Execute(ctx context.Context) (Result, error) {
	return s.children[s.picker.pick()].scenario.Execute(ctx)
}

func (s *Mixed) Teardown(ctx context.Context) error {
	var firstErr error
	for _, c := range s.children {
		if err := c.scenario.Teardown(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// weightedPicker turns a set of weights into weighted-random index
// selection. Factored out of Mixed so the selection math itself is
// unit-testable without needing real, cluster-dependent sub-scenarios.
type weightedPicker struct {
	cumulative []float64
	total      float64
}

func newWeightedPicker(weights []float64) weightedPicker {
	cumulative := make([]float64, len(weights))
	var running float64
	for i, w := range weights {
		running += w
		cumulative[i] = running
	}
	return weightedPicker{cumulative: cumulative, total: running}
}

// pick returns an index in [0, len(weights)) with probability
// proportional to that index's weight.
func (p weightedPicker) pick() int {
	r := rand.Float64() * p.total
	for i, cum := range p.cumulative {
		if r < cum {
			return i
		}
	}
	// Only reachable via floating-point rounding at the very top of the
	// range (r == total).
	return len(p.cumulative) - 1
}
