package ramp

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"teleport-auth-stress/internal/collect"
	"teleport-auth-stress/internal/driver"
	"teleport-auth-stress/internal/scenario"
)

type fakeHealthSampler struct{ health GeneratorHealth }

func (f fakeHealthSampler) Sample() GeneratorHealth { return f.health }

func alwaysSucceed(ctx context.Context) (scenario.Result, error) {
	return scenario.Result{Outcome: scenario.Success}, nil
}

func alwaysFail(ctx context.Context) (scenario.Result, error) {
	return scenario.Result{Outcome: scenario.ServerError}, errors.New("simulated failure")
}

func TestRun_RejectsBadPlan(t *testing.T) {
	cases := []Plan{
		{StartRPS: 0, StepRPS: 1, MaxRPS: 10},
		{StartRPS: 1, StepRPS: 0, MaxRPS: 10},
		{StartRPS: 1, StepRPS: 1, MaxRPS: 0},
	}
	for _, plan := range cases {
		if _, err := Run(context.Background(), plan, AbortCriteria{}, GeneratorThresholds{}, driver.ArrivalUniform, alwaysSucceed, fakeHealthSampler{}, nil); err == nil {
			t.Errorf("Run(%+v) expected error", plan)
		}
	}
}

func TestRun_ConvergesOnKnee(t *testing.T) {
	plan := Plan{StartRPS: 200, StepRPS: 200, StepDuration: 100 * time.Millisecond, MaxRPS: 800}
	abort := AbortCriteria{P99LatencyMs: 1000, ErrorRatePct: 1, ThroughputDeficitPct: 50, ConsecutiveBadSteps: 1}

	// Flip to "degraded" via the onStep callback rather than a wall-clock
	// deadline: onStep fires synchronously between steps, so this is an
	// exact step-boundary signal immune to scheduling jitter (a
	// wall-clock boundary computed from nominal step durations drifts
	// against real elapsed time as steps accumulate their own overhead).
	var degraded atomic.Bool
	task := driver.Task(func(ctx context.Context) (scenario.Result, error) {
		if degraded.Load() {
			return scenario.Result{Outcome: scenario.ServerError}, errors.New("cluster degraded")
		}
		return scenario.Result{Outcome: scenario.Success}, nil
	})
	completed := 0
	onStep := func(StepReport) {
		completed++
		if completed == 2 { // after steps 0 and 1 (200, 400 rps) complete
			degraded.Store(true)
		}
	}

	result, err := Run(context.Background(), plan, abort, GeneratorThresholds{}, driver.ArrivalUniform, task, fakeHealthSampler{}, onStep)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Outcome != Converged {
		t.Fatalf("Outcome = %v, want Converged (steps=%+v)", result.Outcome, result.Steps)
	}
	if result.BreakingPointRPS != 400 {
		t.Errorf("BreakingPointRPS = %v, want 400", result.BreakingPointRPS)
	}
	if len(result.Steps) != 3 {
		t.Fatalf("got %d steps, want 3 (stop after first bad step with ConsecutiveBadSteps=1)", len(result.Steps))
	}
	if !result.Steps[0].Pass || !result.Steps[1].Pass {
		t.Errorf("expected first two steps to pass, got %+v", result.Steps[:2])
	}
	if result.Steps[2].Pass {
		t.Errorf("expected third step (600 rps) to fail, got %+v", result.Steps[2])
	}
}

func TestRun_GeneratorLimited_OverridesOtherwisePassingStep(t *testing.T) {
	plan := Plan{StartRPS: 100, StepRPS: 100, StepDuration: 30 * time.Millisecond, MaxRPS: 100}
	abort := AbortCriteria{P99LatencyMs: 1000, ErrorRatePct: 100, ThroughputDeficitPct: 100, ConsecutiveBadSteps: 5}
	thresholds := GeneratorThresholds{MaxCPUPercent: 50}
	saturated := fakeHealthSampler{health: GeneratorHealth{CPUPercent: 99}}

	result, err := Run(context.Background(), plan, abort, thresholds, driver.ArrivalUniform, alwaysSucceed, saturated, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Outcome != GeneratorLimited {
		t.Fatalf("Outcome = %v, want GeneratorLimited (steps=%+v)", result.Outcome, result.Steps)
	}
	if result.Reason == "" {
		t.Error("expected a non-empty Reason for GeneratorLimited")
	}
	if len(result.Steps) != 1 || !result.Steps[0].GeneratorLimited {
		t.Errorf("expected the single step to be marked GeneratorLimited, got %+v", result.Steps)
	}
	if result.Steps[0].Pass {
		t.Error("a generator-limited step must not be reported as passing, even though the abort criteria alone were lenient enough to pass")
	}
}

func TestRun_Inconclusive_WhenFirstStepFails(t *testing.T) {
	plan := Plan{StartRPS: 100, StepRPS: 100, StepDuration: 20 * time.Millisecond, MaxRPS: 500}
	abort := AbortCriteria{P99LatencyMs: 1000, ErrorRatePct: 1, ThroughputDeficitPct: 50, ConsecutiveBadSteps: 2}

	result, err := Run(context.Background(), plan, abort, GeneratorThresholds{}, driver.ArrivalUniform, alwaysFail, fakeHealthSampler{}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Outcome != Inconclusive {
		t.Fatalf("Outcome = %v, want Inconclusive (steps=%+v)", result.Outcome, result.Steps)
	}
	if result.BreakingPointRPS != 0 {
		t.Errorf("BreakingPointRPS = %v, want 0 for an inconclusive run", result.BreakingPointRPS)
	}
	if len(result.Steps) != abort.ConsecutiveBadSteps {
		t.Errorf("got %d steps, want %d (stop after ConsecutiveBadSteps failures)", len(result.Steps), abort.ConsecutiveBadSteps)
	}
}

func TestRun_StopsAtMaxRPS_AllStepsPassing(t *testing.T) {
	plan := Plan{StartRPS: 100, StepRPS: 100, StepDuration: 15 * time.Millisecond, MaxRPS: 300}
	abort := AbortCriteria{P99LatencyMs: 1000, ErrorRatePct: 1, ThroughputDeficitPct: 50, ConsecutiveBadSteps: 99}

	result, err := Run(context.Background(), plan, abort, GeneratorThresholds{}, driver.ArrivalUniform, alwaysSucceed, fakeHealthSampler{}, nil)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if result.Outcome != Converged {
		t.Fatalf("Outcome = %v, want Converged", result.Outcome)
	}
	if result.BreakingPointRPS != 300 {
		t.Errorf("BreakingPointRPS = %v, want 300 (maxRPS, all steps passed)", result.BreakingPointRPS)
	}
	if len(result.Steps) != 3 {
		t.Errorf("got %d steps, want 3 (100, 200, 300)", len(result.Steps))
	}
}

func TestRun_OnStepCallback(t *testing.T) {
	plan := Plan{StartRPS: 100, StepRPS: 100, StepDuration: 10 * time.Millisecond, MaxRPS: 200}
	abort := AbortCriteria{P99LatencyMs: 1000, ErrorRatePct: 1, ThroughputDeficitPct: 50, ConsecutiveBadSteps: 99}

	var seen []float64
	_, err := Run(context.Background(), plan, abort, GeneratorThresholds{}, driver.ArrivalUniform, alwaysSucceed, fakeHealthSampler{}, func(s StepReport) {
		seen = append(seen, s.OfferedRPS)
	})
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(seen) != 2 || seen[0] != 100 || seen[1] != 200 {
		t.Errorf("onStep saw %v, want [100 200]", seen)
	}
}

func TestEvaluateStep(t *testing.T) {
	abort := AbortCriteria{P99LatencyMs: 100, ErrorRatePct: 1, ThroughputDeficitPct: 5}

	t.Run("passes within all thresholds", func(t *testing.T) {
		c := collect.New()
		for i := 0; i < 100; i++ {
			c.Add(10*time.Millisecond, scenario.Success, 0)
		}
		snap := c.Snapshot(100, time.Second)
		pass, reasons := evaluateStep(snap, abort)
		if !pass {
			t.Errorf("expected pass, got failures: %v", reasons)
		}
	})

	t.Run("fails on p99 latency", func(t *testing.T) {
		c := collect.New()
		for i := 0; i < 100; i++ {
			c.Add(500*time.Millisecond, scenario.Success, 0)
		}
		snap := c.Snapshot(100, time.Second)
		pass, reasons := evaluateStep(snap, abort)
		if pass || len(reasons) == 0 {
			t.Errorf("expected failure on p99 latency, got pass=%v reasons=%v", pass, reasons)
		}
	})

	t.Run("lockouts don't fail the error rate check", func(t *testing.T) {
		c := collect.New()
		for i := 0; i < 50; i++ {
			c.Add(10*time.Millisecond, scenario.Success, 0)
		}
		for i := 0; i < 50; i++ {
			c.Add(10*time.Millisecond, scenario.Lockout, 0)
		}
		snap := c.Snapshot(100, time.Second)
		pass, reasons := evaluateStep(snap, abort)
		if !pass {
			t.Errorf("a 50%% raw error rate that's entirely lockouts must still pass abort criteria, got reasons=%v", reasons)
		}
	})

	t.Run("fails on throughput deficit", func(t *testing.T) {
		c := collect.New()
		for i := 0; i < 50; i++ {
			c.Add(10*time.Millisecond, scenario.Success, 0)
		}
		snap := c.Snapshot(100, time.Second) // offered 100, achieved 50 -> 50% deficit
		pass, reasons := evaluateStep(snap, abort)
		if pass || len(reasons) == 0 {
			t.Errorf("expected failure on throughput deficit, got pass=%v reasons=%v", pass, reasons)
		}
	})
}
