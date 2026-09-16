package aggregate

import (
	"path/filepath"
	"testing"
	"time"

	"teleport-auth-stress/internal/collect"
	"teleport-auth-stress/internal/ramp"
	"teleport-auth-stress/internal/scenario"
)

func exportRaw(t *testing.T, offeredRPS float64, n int, outcome scenario.Outcome, latency time.Duration) collect.RawData {
	t.Helper()
	c := collect.New()
	for i := 0; i < n; i++ {
		c.Add(latency, outcome, 1)
	}
	raw, err := c.Export(offeredRPS)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	return raw
}

func TestWriteReadRawSteps_RoundTrip(t *testing.T) {
	dir := t.TempDir()

	shard0 := RawStep{StepIndex: 0, ShardIndex: 0, Data: exportRaw(t, 50, 100, scenario.Success, 10*time.Millisecond)}
	shard1 := RawStep{StepIndex: 0, ShardIndex: 1, Data: exportRaw(t, 50, 100, scenario.Success, 12*time.Millisecond)}

	if err := WriteRawStep(dir, shard0); err != nil {
		t.Fatalf("WriteRawStep: %v", err)
	}
	if err := WriteRawStep(dir, shard1); err != nil {
		t.Fatalf("WriteRawStep: %v", err)
	}

	// Shards must not collide on filename.
	if filepath.Base(fileName(shard0)) == filepath.Base(fileName(shard1)) {
		t.Fatal("shard0 and shard1 produced the same filename")
	}

	got, err := ReadRawSteps(dir)
	if err != nil {
		t.Fatalf("ReadRawSteps: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d raw steps, want 2", len(got))
	}
}

func TestReadRawSteps_EmptyDirErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := ReadRawSteps(dir); err == nil {
		t.Error("expected error reading an empty results directory")
	}
}

func TestMerge_RejectsEmptyInput(t *testing.T) {
	if _, err := Merge(nil, time.Second, ramp.AbortCriteria{}, ramp.GeneratorThresholds{}); err == nil {
		t.Error("expected error merging zero raw steps")
	}
}

func TestMerge_SumsOfferedRPSAndFindsBreakingPoint(t *testing.T) {
	abort := ramp.AbortCriteria{P99LatencyMs: 100, ErrorRatePct: 1, ThroughputDeficitPct: 10, ConsecutiveBadSteps: 99}

	// 4 shards, 2 steps. Step 0: all shards fast/clean (should pass).
	// Step 1: all shards slow (should fail on p99 latency).
	var raws []RawStep
	for shard := 0; shard < 4; shard++ {
		raws = append(raws,
			RawStep{StepIndex: 0, ShardIndex: shard, Data: exportRaw(t, 25, 50, scenario.Success, 10*time.Millisecond)},
			RawStep{StepIndex: 1, ShardIndex: shard, Data: exportRaw(t, 25, 50, scenario.Success, 500*time.Millisecond)},
		)
	}

	result, err := Merge(raws, time.Second, abort, ramp.GeneratorThresholds{})
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if len(result.Steps) != 2 {
		t.Fatalf("got %d merged steps, want 2", len(result.Steps))
	}

	step0 := result.Steps[0]
	if step0.OfferedRPS != 100 { // 25 * 4 shards
		t.Errorf("step0 OfferedRPS = %v, want 100 (fleet-wide sum)", step0.OfferedRPS)
	}
	if step0.Snapshot.Total != 200 { // 50 samples * 4 shards
		t.Errorf("step0 Total = %d, want 200", step0.Snapshot.Total)
	}
	if !step0.Pass {
		t.Errorf("step0 should pass, got FailReasons=%v", step0.FailReasons)
	}

	step1 := result.Steps[1]
	if step1.Pass {
		t.Errorf("step1 (500ms latency) should fail p99 threshold, got pass with reasons=%v", step1.FailReasons)
	}

	if result.Outcome != ramp.Converged {
		t.Fatalf("Outcome = %v, want Converged", result.Outcome)
	}
	if result.BreakingPointRPS != 100 {
		t.Errorf("BreakingPointRPS = %v, want 100", result.BreakingPointRPS)
	}
}

func TestMerge_GeneratorLimitedIfAnyShardSaturated(t *testing.T) {
	abort := ramp.AbortCriteria{P99LatencyMs: 1000, ErrorRatePct: 100, ThroughputDeficitPct: 100, ConsecutiveBadSteps: 99}
	thresholds := ramp.GeneratorThresholds{MaxCPUPercent: 80}

	raws := []RawStep{
		{StepIndex: 0, ShardIndex: 0, Data: exportRaw(t, 50, 10, scenario.Success, time.Millisecond), Health: ramp.GeneratorHealth{CPUPercent: 20}},
		{StepIndex: 0, ShardIndex: 1, Data: exportRaw(t, 50, 10, scenario.Success, time.Millisecond), Health: ramp.GeneratorHealth{CPUPercent: 95}}, // this shard saturated
	}

	result, err := Merge(raws, time.Second, abort, thresholds)
	if err != nil {
		t.Fatalf("Merge: %v", err)
	}
	if result.Outcome != ramp.GeneratorLimited {
		t.Fatalf("Outcome = %v, want GeneratorLimited (one shard's CPU crossed the threshold)", result.Outcome)
	}
	if result.Steps[0].Health.CPUPercent != 95 {
		t.Errorf("merged step health CPUPercent = %v, want 95 (worst across shards)", result.Steps[0].Health.CPUPercent)
	}
}
