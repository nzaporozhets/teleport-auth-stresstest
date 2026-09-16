// Package driver implements the arrival-control loops that decide when
// each virtual user's Execute call fires. The open loop is the default
// and the only one that avoids coordinated omission (domain constraint
// #6 in instructions.md): it schedules arrivals at a fixed target rate
// from a Poisson or fixed-interval process and reports latency measured
// from the *intended* send time, regardless of whether a previous call
// has finished. The closed loop exists only for comparison and is never
// the default.
package driver

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"sync"
	"time"

	"teleport-auth-stress/internal/scenario"
)

// Arrival selects how the open loop spaces intended arrival times.
type Arrival string

const (
	ArrivalPoisson Arrival = "poisson"
	ArrivalUniform Arrival = "uniform"
)

// Task performs one scenario operation. Implementations must not panic —
// a scenario failure degrades one virtual user, never the run (see
// instructions.md "Engineering standards"); the driver does not recover
// from panics on the caller's behalf.
type Task func(ctx context.Context) (scenario.Result, error)

// Sample is what one Task call produced, from the driver's perspective.
type Sample struct {
	// IntendedAt is when this call was scheduled to start. For the open
	// loop this is the fixed-rate arrival time, independent of when a
	// worker actually became free; for the closed loop it equals
	// StartedAt by construction (see RunClosedLoop).
	IntendedAt time.Time
	StartedAt  time.Time
	FinishedAt time.Time
	Result     scenario.Result
	Err        error
}

// OpenLoopLatency is the latency an open-loop consumer should record:
// measured from intended send time, so queueing delay is visible instead
// of hidden by coordinated omission.
func (s Sample) OpenLoopLatency() time.Duration { return s.FinishedAt.Sub(s.IntendedAt) }

// OnSample receives one completed Sample. It is called concurrently from
// many goroutines under the open loop (one per in-flight Task) and must
// be safe for concurrent use.
type OnSample func(Sample)

// poissonInterval draws one exponentially-distributed interarrival time
// with the given mean, per a Poisson arrival process.
func poissonInterval(rng *rand.Rand, mean time.Duration) time.Duration {
	u := rng.Float64()
	for u == 0 { // exclude the zero case: log(0) is -Inf
		u = rng.Float64()
	}
	return time.Duration(-math.Log(u) * float64(mean))
}

// RunOpenLoop schedules Task calls at rateRPS according to arrival, for
// duration, calling onSample once each completes. Each call runs in its
// own goroutine the moment its scheduled time arrives — the loop never
// waits for a previous call to finish, which is what makes this open-loop
// (see package doc). It returns once every scheduled call has completed
// or ctx is done.
func RunOpenLoop(ctx context.Context, rateRPS float64, arrival Arrival, duration time.Duration, task Task, onSample OnSample) error {
	if rateRPS <= 0 {
		return fmt.Errorf("rateRPS must be > 0, got %v", rateRPS)
	}
	switch arrival {
	case ArrivalPoisson, ArrivalUniform:
	default:
		return fmt.Errorf("unknown arrival process %q", arrival)
	}

	meanInterval := time.Duration(float64(time.Second) / rateRPS)
	rng := rand.New(rand.NewSource(time.Now().UnixNano()))

	start := time.Now()
	deadline := start.Add(duration)

	var wg sync.WaitGroup
	next := start
	for !next.After(deadline) {
		if sleep := time.Until(next); sleep > 0 {
			timer := time.NewTimer(sleep)
			select {
			case <-timer.C:
			case <-ctx.Done():
				timer.Stop()
				wg.Wait()
				return ctx.Err()
			}
		} else {
			select {
			case <-ctx.Done():
				wg.Wait()
				return ctx.Err()
			default:
			}
		}

		intended := next
		wg.Add(1)
		go func() {
			defer wg.Done()
			started := time.Now()
			result, err := task(ctx)
			finished := time.Now()
			onSample(Sample{IntendedAt: intended, StartedAt: started, FinishedAt: finished, Result: result, Err: err})
		}()

		if arrival == ArrivalPoisson {
			next = next.Add(poissonInterval(rng, meanInterval))
		} else {
			next = next.Add(meanInterval)
		}
	}

	wg.Wait()
	return nil
}

// RunClosedLoop runs `concurrency` workers in a tight loop, each starting
// its next Task call as soon as the previous one finishes, for duration.
// This is the closed-loop mode instructions.md allows only as a
// non-default comparison option: because IntendedAt == StartedAt here,
// it structurally cannot show queueing delay the way the open loop does.
func RunClosedLoop(ctx context.Context, concurrency int, duration time.Duration, task Task, onSample OnSample) error {
	if concurrency <= 0 {
		return fmt.Errorf("concurrency must be > 0, got %d", concurrency)
	}
	deadline := time.Now().Add(duration)

	var wg sync.WaitGroup
	for i := 0; i < concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for time.Now().Before(deadline) {
				select {
				case <-ctx.Done():
					return
				default:
				}
				started := time.Now()
				result, err := task(ctx)
				finished := time.Now()
				onSample(Sample{IntendedAt: started, StartedAt: started, FinishedAt: finished, Result: result, Err: err})
			}
		}()
	}
	wg.Wait()
	return ctx.Err()
}
