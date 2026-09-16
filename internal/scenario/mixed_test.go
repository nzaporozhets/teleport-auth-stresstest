package scenario

import (
	"context"
	"testing"

	"teleport-auth-stress/internal/config"
)

func TestMixed_Name(t *testing.T) {
	s := &Mixed{}
	if s.Name() != "mixed" {
		t.Errorf("Name() = %q, want mixed", s.Name())
	}
}

func TestMixed_Setup_RequiresConfig(t *testing.T) {
	s := &Mixed{}
	if err := s.Setup(context.Background(), &Env{}); err == nil {
		t.Fatal("expected error when env.Config is nil")
	}
}

func TestMixed_Setup_RequiresAtLeastTwoWeights(t *testing.T) {
	s := &Mixed{}
	err := s.Setup(context.Background(), &Env{Config: &config.Config{Load: config.LoadSpec{
		Mixed: config.Mixed{Weights: map[config.ScenarioName]float64{config.ScenarioCertRenewal: 1}},
	}}})
	if err == nil {
		t.Fatal("expected error when fewer than two scenarios are weighted")
	}
}

func TestMixed_Setup_RejectsUnknownScenario(t *testing.T) {
	s := &Mixed{}
	err := s.Setup(context.Background(), &Env{Config: &config.Config{Load: config.LoadSpec{
		Mixed: config.Mixed{Weights: map[config.ScenarioName]float64{
			config.ScenarioCertRenewal: 1,
			"not-a-real-scenario":      1,
		}},
	}}})
	if err == nil {
		t.Fatal("expected error for a weight key naming an unknown scenario")
	}
}

func TestMixed_Setup_RejectsNonPositiveWeight(t *testing.T) {
	s := &Mixed{}
	err := s.Setup(context.Background(), &Env{Config: &config.Config{Load: config.LoadSpec{
		Mixed: config.Mixed{Weights: map[config.ScenarioName]float64{
			config.ScenarioCertRenewal:        1,
			config.ScenarioLocalLoginWebAuthn: 0,
		}},
	}}})
	if err == nil {
		t.Fatal("expected error for a non-positive weight")
	}
}

func TestMixed_Teardown_NoChildrenIsNoop(t *testing.T) {
	s := &Mixed{}
	if err := s.Teardown(context.Background()); err != nil {
		t.Errorf("Teardown with no children should be a no-op, got: %v", err)
	}
}

func TestNewSubScenario_KnownNames(t *testing.T) {
	names := []config.ScenarioName{
		config.ScenarioCertRenewal,
		config.ScenarioLocalLoginWebAuthn,
		config.ScenarioLocalLoginTOTP,
		config.ScenarioBotJoinRenew,
		config.ScenarioRouteCertIssuance,
	}
	for _, name := range names {
		sub, err := newSubScenario(name)
		if err != nil {
			t.Errorf("newSubScenario(%q): %v", name, err)
			continue
		}
		if sub.Name() != string(name) {
			t.Errorf("newSubScenario(%q).Name() = %q, want %q", name, sub.Name(), name)
		}
	}
}

func TestNewSubScenario_RejectsMixedAndUnknown(t *testing.T) {
	for _, name := range []config.ScenarioName{config.ScenarioMixed, "bogus"} {
		if _, err := newSubScenario(name); err == nil {
			t.Errorf("newSubScenario(%q): expected an error", name)
		}
	}
}

// TestWeightedPicker_ConvergesToWeights is a statistical test with a
// generous tolerance: across 100,000 draws, a weight of 1 vs. 3 should
// land close to a 25%/75% split. The tolerance band is wide enough that
// this should not flake in practice while still catching a broken
// selection (e.g. uniform selection ignoring weights entirely, or an
// inverted comparison).
func TestWeightedPicker_ConvergesToWeights(t *testing.T) {
	p := newWeightedPicker([]float64{1, 3})
	const n = 100000
	var counts [2]int
	for i := 0; i < n; i++ {
		idx := p.pick()
		if idx < 0 || idx > 1 {
			t.Fatalf("pick() returned out-of-range index %d", idx)
		}
		counts[idx]++
	}
	got0 := float64(counts[0]) / n
	if got0 < 0.20 || got0 > 0.30 {
		t.Errorf("index 0 (weight 1 of 4) picked %.1f%% of the time, want ~25%%", got0*100)
	}
}

func TestWeightedPicker_SingleWeightAlwaysPicksIt(t *testing.T) {
	p := newWeightedPicker([]float64{5})
	for i := 0; i < 100; i++ {
		if got := p.pick(); got != 0 {
			t.Fatalf("pick() = %d, want 0 (only one weighted entry)", got)
		}
	}
}
