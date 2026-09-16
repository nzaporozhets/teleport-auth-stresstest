package collect

import (
	"sync"
	"testing"
	"time"

	"teleport-auth-stress/internal/scenario"
)

func TestCollector_SnapshotBasics(t *testing.T) {
	c := New()

	// 90 successes at 10ms, 10 client errors at 50ms.
	for i := 0; i < 90; i++ {
		c.Add(10*time.Millisecond, scenario.Success, 128)
	}
	for i := 0; i < 10; i++ {
		c.Add(50*time.Millisecond, scenario.ClientError, 0)
	}

	snap := c.Snapshot(100, time.Second)

	if snap.Total != 100 {
		t.Errorf("Total = %d, want 100", snap.Total)
	}
	if snap.Outcomes[scenario.Success] != 90 {
		t.Errorf("Success count = %d, want 90", snap.Outcomes[scenario.Success])
	}
	if snap.Outcomes[scenario.ClientError] != 10 {
		t.Errorf("ClientError count = %d, want 10", snap.Outcomes[scenario.ClientError])
	}
	if got, want := snap.ErrorRatePct(), 10.0; got != want {
		t.Errorf("ErrorRatePct() = %v, want %v", got, want)
	}
	if got, want := snap.AchievedRPS, 100.0; got != want {
		t.Errorf("AchievedRPS = %v, want %v", got, want)
	}
	if snap.Bytes != 90*128 {
		t.Errorf("Bytes = %d, want %d", snap.Bytes, 90*128)
	}

	// p50 should land near 10ms (90% of samples), p99.9 near 50ms.
	if diff := snap.P50 - 10*time.Millisecond; diff > time.Millisecond || diff < -time.Millisecond {
		t.Errorf("P50 = %v, want ~10ms", snap.P50)
	}
	if diff := snap.P999 - 50*time.Millisecond; diff > time.Millisecond || diff < -time.Millisecond {
		t.Errorf("P99.9 = %v, want ~50ms", snap.P999)
	}
}

func TestCollector_AbortErrorRatePct_ExcludesLockout(t *testing.T) {
	c := New()
	for i := 0; i < 80; i++ {
		c.Add(10*time.Millisecond, scenario.Success, 0)
	}
	for i := 0; i < 15; i++ {
		c.Add(10*time.Millisecond, scenario.Lockout, 0)
	}
	for i := 0; i < 5; i++ {
		c.Add(10*time.Millisecond, scenario.ServerError, 0)
	}
	snap := c.Snapshot(100, time.Second)

	if got, want := snap.ErrorRatePct(), 20.0; got != want {
		t.Errorf("ErrorRatePct() = %v, want %v (includes lockouts)", got, want)
	}
	if got, want := snap.AbortErrorRatePct(), 5.0; got != want {
		t.Errorf("AbortErrorRatePct() = %v, want %v (excludes lockouts)", got, want)
	}
}

func TestCollector_EmptySnapshot(t *testing.T) {
	c := New()
	snap := c.Snapshot(20, time.Second)
	if snap.Total != 0 || snap.ErrorRatePct() != 0 || snap.AchievedRPS != 0 {
		t.Errorf("empty snapshot should be all zero, got %+v", snap)
	}
}

func TestCollector_ConcurrentAdd(t *testing.T) {
	c := New()
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			outcome := scenario.Success
			if i%10 == 0 {
				outcome = scenario.ServerError
			}
			c.Add(time.Duration(i+1)*time.Millisecond, outcome, 1)
		}(i)
	}
	wg.Wait()

	snap := c.Snapshot(50, time.Second)
	if snap.Total != 50 {
		t.Errorf("Total = %d, want 50", snap.Total)
	}
}

func TestExportMergeRaw_LosslessAgainstGroundTruth(t *testing.T) {
	// Two "pods" record disjoint samples...
	podA := New()
	for i := 1; i <= 100; i++ {
		podA.Add(time.Duration(i)*time.Millisecond, scenario.Success, 10)
	}
	podB := New()
	for i := 101; i <= 250; i++ {
		podB.Add(time.Duration(i)*time.Millisecond, scenario.Success, 10)
	}
	for i := 0; i < 5; i++ {
		podB.Add(50*time.Millisecond, scenario.RateLimited, 0)
	}

	rawA, err := podA.Export(50)
	if err != nil {
		t.Fatalf("podA.Export: %v", err)
	}
	rawB, err := podB.Export(50)
	if err != nil {
		t.Fatalf("podB.Export: %v", err)
	}

	merged, err := MergeRaw([]RawData{rawA, rawB}, time.Second)
	if err != nil {
		t.Fatalf("MergeRaw: %v", err)
	}

	// ...and a single "ground truth" collector records the exact same
	// union directly, with no export/merge round-trip.
	truth := New()
	for i := 1; i <= 100; i++ {
		truth.Add(time.Duration(i)*time.Millisecond, scenario.Success, 10)
	}
	for i := 101; i <= 250; i++ {
		truth.Add(time.Duration(i)*time.Millisecond, scenario.Success, 10)
	}
	for i := 0; i < 5; i++ {
		truth.Add(50*time.Millisecond, scenario.RateLimited, 0)
	}
	want := truth.Snapshot(100, time.Second)

	if merged.Total != want.Total {
		t.Errorf("Total = %d, want %d", merged.Total, want.Total)
	}
	if merged.OfferedRPS != 100 { // 50 + 50, summed across pods
		t.Errorf("OfferedRPS = %v, want 100 (sum of both pods' shards)", merged.OfferedRPS)
	}
	if merged.Bytes != want.Bytes {
		t.Errorf("Bytes = %d, want %d", merged.Bytes, want.Bytes)
	}
	if merged.Outcomes[scenario.Success] != want.Outcomes[scenario.Success] {
		t.Errorf("Success count = %d, want %d", merged.Outcomes[scenario.Success], want.Outcomes[scenario.Success])
	}
	if merged.Outcomes[scenario.RateLimited] != want.Outcomes[scenario.RateLimited] {
		t.Errorf("RateLimited count = %d, want %d", merged.Outcomes[scenario.RateLimited], want.Outcomes[scenario.RateLimited])
	}
	// The core claim: percentiles from the merged histogram exactly
	// match a histogram that recorded the same values directly — this is
	// what "HDR histograms merge losslessly" means in practice, not an
	// approximation.
	if merged.P50 != want.P50 {
		t.Errorf("P50 = %v, want %v (exact match, not approximate)", merged.P50, want.P50)
	}
	if merged.P90 != want.P90 {
		t.Errorf("P90 = %v, want %v", merged.P90, want.P90)
	}
	if merged.P99 != want.P99 {
		t.Errorf("P99 = %v, want %v", merged.P99, want.P99)
	}
	if merged.P999 != want.P999 {
		t.Errorf("P999 = %v, want %v", merged.P999, want.P999)
	}
}

func TestMergeRaw_RejectsEmptyInput(t *testing.T) {
	if _, err := MergeRaw(nil, time.Second); err == nil {
		t.Error("expected error merging zero RawData")
	}
}

func TestMergeRaw_RejectsUnknownOutcome(t *testing.T) {
	c := New()
	c.Add(time.Millisecond, scenario.Success, 0)
	raw, err := c.Export(10)
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	raw.Outcomes["not-a-real-outcome"] = 1
	if _, err := MergeRaw([]RawData{raw}, time.Second); err == nil {
		t.Error("expected error merging an unrecognized outcome string")
	}
}

func TestCollector_ClampsOutOfRangeLatency(t *testing.T) {
	c := New()
	// Negative/zero latency shouldn't happen in practice, but Add must
	// not panic or drop the sample from the count.
	c.Add(0, scenario.Success, 0)
	c.Add(10*time.Hour, scenario.Timeout, 0)

	snap := c.Snapshot(1, time.Second)
	if snap.Total != 2 {
		t.Errorf("Total = %d, want 2", snap.Total)
	}
}
