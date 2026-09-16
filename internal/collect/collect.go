// Package collect aggregates driver samples into an HDR latency
// histogram and an error-class breakdown for one run. Full-fidelity HDR
// histograms are used rather than fixed Prometheus-style buckets, per
// instructions.md's ramp/breaking-point logic: bucket boundaries would
// round away exactly the answer this toolkit exists to find.
package collect

import (
	"fmt"
	"sync"
	"time"

	hdrhistogram "github.com/HdrHistogram/hdrhistogram-go"

	"teleport-auth-stress/internal/scenario"
)

// Collector accumulates samples from a single run. Safe for concurrent
// Add calls: the open-loop driver invokes its OnSample callback from many
// concurrent goroutines (one per in-flight Task).
type Collector struct {
	mu       sync.Mutex
	hist     *hdrhistogram.Histogram
	outcomes map[scenario.Outcome]int64
	total    int64
	bytes    int64
}

// latencyFloorMicros / latencyCeilingMicros bound the histogram: 1
// microsecond lowest discernible value, 5 minutes highest trackable
// value, comfortably above any latency this toolkit would consider a
// meaningful sample (calls that take longer are already well past any
// reasonable abort threshold). 3 significant figures is the standard HDR
// tradeoff of memory for precision at this scale.
const (
	latencyFloorMicros   = 1
	latencyCeilingMicros = int64(5 * time.Minute / time.Microsecond)
	significantFigures   = 3
)

// New creates an empty Collector.
func New() *Collector {
	return &Collector{
		hist:     hdrhistogram.New(latencyFloorMicros, latencyCeilingMicros, significantFigures),
		outcomes: make(map[scenario.Outcome]int64),
	}
}

// Add records one completed sample. Latency is recorded regardless of
// outcome — a slow failure is still informative and excluding it would
// bias percentiles toward successes only.
func (c *Collector) Add(latency time.Duration, outcome scenario.Outcome, bytes int64) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.total++
	c.outcomes[outcome]++
	c.bytes += bytes

	micros := latency.Microseconds()
	if micros < latencyFloorMicros {
		micros = latencyFloorMicros
	}
	if micros > latencyCeilingMicros {
		micros = latencyCeilingMicros
	}
	// RecordValue only fails outside [floor, ceiling], which the clamps
	// above already guarantee against.
	_ = c.hist.RecordValue(micros)
}

// Snapshot is a point-in-time summary of everything collected so far.
type Snapshot struct {
	OfferedRPS  float64
	AchievedRPS float64
	Total       int64
	Bytes       int64
	Outcomes    map[scenario.Outcome]int64
	P50         time.Duration
	P90         time.Duration
	P99         time.Duration
	P999        time.Duration
}

// ErrorRatePct is the percentage of samples that were not Success. This
// is the raw, informational rate for reports; the ramp package (M4)
// uses AbortErrorRatePct, not this, to decide whether a step passes.
func (s Snapshot) ErrorRatePct() float64 {
	if s.Total == 0 {
		return 0
	}
	errors := s.Total - s.Outcomes[scenario.Success]
	return 100 * float64(errors) / float64(s.Total)
}

// AbortErrorRatePct is ErrorRatePct with Lockout excluded. Domain
// constraint #2: once a ramp starts producing errors, lockouts cascade
// and would turn a latency/capacity problem into a fake wall of
// authentication failures if they counted toward the rate that drives
// abort criteria — so they must not.
func (s Snapshot) AbortErrorRatePct() float64 {
	if s.Total == 0 {
		return 0
	}
	nonAbortErrors := s.Total - s.Outcomes[scenario.Success] - s.Outcomes[scenario.Lockout]
	return 100 * float64(nonAbortErrors) / float64(s.Total)
}

// Snapshot summarizes the run so far. offeredRPS is the configured
// target rate (not derived from samples); elapsed is the wall-clock time
// over which achieved throughput is computed.
func (c *Collector) Snapshot(offeredRPS float64, elapsed time.Duration) Snapshot {
	c.mu.Lock()
	defer c.mu.Unlock()

	outcomes := make(map[scenario.Outcome]int64, len(c.outcomes))
	for k, v := range c.outcomes {
		outcomes[k] = v
	}

	var achievedRPS float64
	if elapsed > 0 {
		achievedRPS = float64(c.total) / elapsed.Seconds()
	}

	return Snapshot{
		OfferedRPS:  offeredRPS,
		AchievedRPS: achievedRPS,
		Total:       c.total,
		Bytes:       c.bytes,
		Outcomes:    outcomes,
		P50:         percentile(c.hist, 50),
		P90:         percentile(c.hist, 90),
		P99:         percentile(c.hist, 99),
		P999:        percentile(c.hist, 99.9),
	}
}

func percentile(h *hdrhistogram.Histogram, p float64) time.Duration {
	return time.Duration(h.ValueAtPercentile(p)) * time.Microsecond
}

// String renders a compact one-line summary, useful for progress logging.
func (s Snapshot) String() string {
	return fmt.Sprintf("offered=%.1frps achieved=%.1frps total=%d errRate=%.2f%% p50=%v p90=%v p99=%v p99.9=%v",
		s.OfferedRPS, s.AchievedRPS, s.Total, s.ErrorRatePct(), s.P50, s.P90, s.P99, s.P999)
}
