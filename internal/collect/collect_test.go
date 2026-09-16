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
