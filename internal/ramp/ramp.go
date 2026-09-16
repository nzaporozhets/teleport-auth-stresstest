// Package ramp implements the step plan, abort criteria, and knee
// detection described in instructions.md's "Ramp and breaking-point
// logic": warm up, then run each step at a fixed offered rate,
// discarding the settle window after every rate change, until
// consecutiveBadSteps failures or maxRPS is reached. The breaking point
// is the highest offered rate whose step passed.
package ramp

import (
	"context"
	"fmt"
	"time"

	"teleport-auth-stress/internal/collect"
	"teleport-auth-stress/internal/driver"
)

// Plan is the step schedule.
type Plan struct {
	StartRPS     float64
	StepRPS      float64
	StepDuration time.Duration
	Warmup       time.Duration
	Settle       time.Duration
	MaxRPS       float64
}

// AbortCriteria decides whether a step passes.
type AbortCriteria struct {
	P99LatencyMs         float64
	ErrorRatePct         float64
	ThroughputDeficitPct float64
	ConsecutiveBadSteps  int
}

// Outcome is the run-level conclusion.
type Outcome int

const (
	// Converged means the ramp found a genuine breaking point: at least
	// one step passed, the generator was never saturated, and the run
	// stopped either because it hit maxRPS or consecutiveBadSteps.
	Converged Outcome = iota
	// GeneratorLimited means the generator itself saturated (domain
	// constraint #7) during the run — no cluster breaking point can be
	// claimed, regardless of what the step results otherwise showed.
	GeneratorLimited
	// Inconclusive means no step ever passed (including the first one),
	// so there is no breaking point to report at all.
	Inconclusive
)

func (o Outcome) String() string {
	switch o {
	case Converged:
		return "converged"
	case GeneratorLimited:
		return "generator-limited"
	case Inconclusive:
		return "inconclusive"
	default:
		return "unknown"
	}
}

// StepReport is one step's full result.
type StepReport struct {
	OfferedRPS       float64
	Snapshot         collect.Snapshot
	Health           GeneratorHealth
	GeneratorLimited bool
	Pass             bool
	FailReasons      []string
	// RawData is a lossless, mergeable export of this step's histogram
	// and outcome counts (collect.Collector.Export) — carried here, not
	// just the already-percentile-reduced Snapshot, so a sharded run
	// (M5) can persist it for the aggregate command to losslessly merge
	// with other pods' exports of the same step.
	RawData collect.RawData
}

// Result is the whole ramp's outcome.
type Result struct {
	Steps            []StepReport
	Outcome          Outcome
	BreakingPointRPS float64 // meaningful only when Outcome == Converged
	Reason           string  // populated for GeneratorLimited/Inconclusive
}

// healthSampleInterval is how often the generator health sampler is
// polled during a step's measured window. A step lasts at least tens of
// seconds in practice, so this is frequent enough to catch a saturation
// spike without meaningfully perturbing the generator itself.
const healthSampleInterval = 500 * time.Millisecond

// Run executes the step plan against task using the open-loop driver,
// evaluating each step against abort and thresholds, until
// consecutiveBadSteps failures or Plan.MaxRPS is reached. onStep, if
// non-nil, is called synchronously after each step completes (for
// progress logging).
func Run(ctx context.Context, plan Plan, abort AbortCriteria, thresholds GeneratorThresholds, arrival driver.Arrival, task driver.Task, health HealthSampler, onStep func(StepReport)) (*Result, error) {
	if plan.StartRPS <= 0 || plan.StepRPS <= 0 || plan.MaxRPS <= 0 {
		return nil, fmt.Errorf("ramp.Plan must have positive StartRPS, StepRPS, and MaxRPS")
	}

	var steps []StepReport
	consecutiveBad := 0

	for rate, first := plan.StartRPS, true; rate <= plan.MaxRPS; rate, first = rate+plan.StepRPS, false {
		discard := plan.Settle
		if first {
			discard = plan.Warmup
		}
		if discard > 0 {
			if err := driver.RunOpenLoop(ctx, rate, arrival, discard, task, func(driver.Sample) {}); err != nil {
				return nil, fmt.Errorf("discard window at %v rps: %w", rate, err)
			}
		}

		report, err := runStep(ctx, rate, plan.StepDuration, arrival, task, health, abort, thresholds)
		if err != nil {
			return nil, fmt.Errorf("step at %v rps: %w", rate, err)
		}
		steps = append(steps, report)
		if onStep != nil {
			onStep(report)
		}

		if report.Pass {
			consecutiveBad = 0
		} else {
			consecutiveBad++
		}
		if consecutiveBad >= abort.ConsecutiveBadSteps {
			break
		}
	}

	return DetermineOutcome(steps), nil
}

// DetermineOutcome computes the run-level Result from a completed list
// of per-step reports, exactly as Run's own loop does. Exported so the
// aggregate command (M5) can compute the identical run-level verdict
// from merged multi-pod steps that were re-evaluated with EvaluateStep,
// without duplicating this logic.
func DetermineOutcome(steps []StepReport) *Result {
	result := &Result{Steps: steps}

	var anyGeneratorLimited, anyPass bool
	var breakingPoint float64
	for _, s := range steps {
		if s.GeneratorLimited {
			anyGeneratorLimited = true
		}
		if s.Pass {
			anyPass = true
			if s.OfferedRPS > breakingPoint {
				breakingPoint = s.OfferedRPS
			}
		}
	}

	switch {
	case anyGeneratorLimited:
		result.Outcome = GeneratorLimited
		result.Reason = "the generator itself saturated (CPU, goroutines, file descriptors, or ephemeral ports) during at least one step; no cluster breaking point can be attributed from this run"
	case !anyPass:
		result.Outcome = Inconclusive
		result.Reason = "no step passed, including the first one at load.ramp.startRPS; either startRPS is already past the cluster's limit or the abort thresholds are too strict"
	default:
		result.Outcome = Converged
		result.BreakingPointRPS = breakingPoint
	}
	return result
}

func runStep(ctx context.Context, rate float64, duration time.Duration, arrival driver.Arrival, task driver.Task, health HealthSampler, abort AbortCriteria, thresholds GeneratorThresholds) (StepReport, error) {
	collector := collect.New()

	healthCtx, stopHealth := context.WithCancel(ctx)
	healthDone := make(chan GeneratorHealth, 1)
	go func() {
		healthDone <- pollHealth(healthCtx, health)
	}()

	start := time.Now()
	err := driver.RunOpenLoop(ctx, rate, arrival, duration, task, func(s driver.Sample) {
		collector.Add(s.OpenLoopLatency(), s.Result.Outcome, s.Result.Bytes)
	})
	elapsed := time.Since(start)
	stopHealth()
	worstHealth := <-healthDone
	if err != nil {
		return StepReport{}, err
	}

	snap := collector.Snapshot(rate, elapsed)
	limited, healthReasons := worstHealth.Exceeds(thresholds)
	pass, abortReasons := EvaluateStep(snap, abort)

	raw, err := collector.Export(rate)
	if err != nil {
		return StepReport{}, fmt.Errorf("exporting raw step data: %w", err)
	}

	return StepReport{
		OfferedRPS:       rate,
		Snapshot:         snap,
		Health:           worstHealth,
		GeneratorLimited: limited,
		Pass:             pass && !limited,
		FailReasons:      append(abortReasons, healthReasons...),
		RawData:          raw,
	}, nil
}

// pollHealth samples health on a ticker until ctx is done, returning
// the worst (max-per-field) reading seen. It always returns at least
// one sample (taken immediately, before the first tick) so a step
// shorter than healthSampleInterval still gets a reading.
func pollHealth(ctx context.Context, health HealthSampler) GeneratorHealth {
	result := health.Sample()
	ticker := time.NewTicker(healthSampleInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return result
		case <-ticker.C:
			result = WorstHealth(result, health.Sample())
		}
	}
}

// EvaluateStep decides whether snap passes abort's thresholds. Exported
// so the aggregate command (M5) can re-evaluate a merged multi-pod
// Snapshot with the same logic a live single-shard step used — the
// merged snapshot's stats (percentiles, error rate, achieved rate) are
// what must be evaluated, not an AND/OR of each shard's own verdict,
// since a fleet-wide aggregate can cross a threshold that no individual
// shard did on its own (or vice versa).
func EvaluateStep(snap collect.Snapshot, abort AbortCriteria) (bool, []string) {
	var reasons []string

	p99Ms := float64(snap.P99) / float64(time.Millisecond)
	if abort.P99LatencyMs > 0 && p99Ms > abort.P99LatencyMs {
		reasons = append(reasons, fmt.Sprintf("p99 latency %.1fms exceeds threshold %.1fms", p99Ms, abort.P99LatencyMs))
	}

	errRate := snap.AbortErrorRatePct()
	if errRate > abort.ErrorRatePct {
		reasons = append(reasons, fmt.Sprintf("error rate %.2f%% (excluding lockouts) exceeds threshold %.2f%%", errRate, abort.ErrorRatePct))
	}

	var deficitPct float64
	if snap.OfferedRPS > 0 {
		deficitPct = 100 * (snap.OfferedRPS - snap.AchievedRPS) / snap.OfferedRPS
	}
	if deficitPct > abort.ThroughputDeficitPct {
		reasons = append(reasons, fmt.Sprintf("throughput deficit %.2f%% exceeds threshold %.2f%%", deficitPct, abort.ThroughputDeficitPct))
	}

	return len(reasons) == 0, reasons
}
