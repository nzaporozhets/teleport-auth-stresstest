package driver

import (
	"context"
	"math"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"teleport-auth-stress/internal/scenario"
)

func TestPoissonInterval_MatchesExpectedMean(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	mean := 10 * time.Millisecond
	const n = 200000

	var sum time.Duration
	for i := 0; i < n; i++ {
		sum += poissonInterval(rng, mean)
	}
	got := sum / time.Duration(n)

	// Statistical, not exact: allow 5% slack on a 200k-sample mean.
	tolerance := time.Duration(float64(mean) * 0.05)
	if diff := got - mean; diff > tolerance || diff < -tolerance {
		t.Errorf("mean interarrival time = %v, want ~%v (+/- %v)", got, mean, tolerance)
	}
}

func instantTask(ctx context.Context) (scenario.Result, error) {
	return scenario.Result{Outcome: scenario.Success}, nil
}

func TestRunOpenLoop_UniformAchievesRoughlyTargetCount(t *testing.T) {
	var n atomic.Int64
	var mu sync.Mutex
	var samples []Sample

	const rate = 500.0 // RPS
	const duration = 200 * time.Millisecond

	err := RunOpenLoop(context.Background(), rate, ArrivalUniform, duration, instantTask, func(s Sample) {
		n.Add(1)
		mu.Lock()
		samples = append(samples, s)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("RunOpenLoop: %v", err)
	}

	want := rate * duration.Seconds()
	got := float64(n.Load())
	// Generous tolerance: this is a scheduling-loop sanity check, not the
	// precision claim (that's instructions.md's live 2%-of-offered
	// acceptance test against a real cluster, which needs a real cluster).
	if math.Abs(got-want) > want*0.25+2 {
		t.Errorf("got %v samples, want ~%v (rate=%v over %v)", got, want, rate, duration)
	}

	for _, s := range samples {
		if s.FinishedAt.Before(s.IntendedAt) {
			t.Errorf("sample finished before it was intended to start: %+v", s)
		}
	}
}

func TestRunOpenLoop_RejectsBadInput(t *testing.T) {
	if err := RunOpenLoop(context.Background(), 0, ArrivalUniform, time.Second, instantTask, func(Sample) {}); err == nil {
		t.Error("expected error for rateRPS <= 0")
	}
	if err := RunOpenLoop(context.Background(), 10, "bogus", time.Second, instantTask, func(Sample) {}); err == nil {
		t.Error("expected error for unknown arrival process")
	}
}

func TestRunOpenLoop_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := RunOpenLoop(ctx, 10, ArrivalUniform, time.Second, instantTask, func(Sample) {})
	if err == nil {
		t.Error("expected context error when context is already cancelled")
	}
}

func TestRunClosedLoop_LatencyMeasuredFromStart(t *testing.T) {
	var mu sync.Mutex
	var samples []Sample

	err := RunClosedLoop(context.Background(), 4, 100*time.Millisecond, instantTask, func(s Sample) {
		mu.Lock()
		samples = append(samples, s)
		mu.Unlock()
	})
	if err != nil {
		t.Fatalf("RunClosedLoop: %v", err)
	}
	if len(samples) == 0 {
		t.Fatal("expected at least one sample")
	}
	for _, s := range samples {
		if !s.IntendedAt.Equal(s.StartedAt) {
			t.Errorf("closed loop sample must have IntendedAt == StartedAt, got %v vs %v", s.IntendedAt, s.StartedAt)
		}
	}
}

func TestRunClosedLoop_RejectsBadInput(t *testing.T) {
	if err := RunClosedLoop(context.Background(), 0, time.Second, instantTask, func(Sample) {}); err == nil {
		t.Error("expected error for concurrency <= 0")
	}
}
