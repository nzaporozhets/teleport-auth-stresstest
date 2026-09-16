package attrib

import (
	"fmt"
	"sort"

	"teleport-auth-stress/internal/collect"
	"teleport-auth-stress/internal/ramp"
	"teleport-auth-stress/internal/scenario"
)

// StepMetrics is everything available for one ramp step: server-side
// snapshots taken at the start and end of the step (per scrape target
// name), plus the generator's own view of that step.
type StepMetrics struct {
	ServerBefore map[string]*Snapshot // by target name (e.g. "auth", "proxy")
	ServerAfter  map[string]*Snapshot
	Generator    collect.Snapshot
	Health       ramp.GeneratorHealth
	WallSeconds  float64
}

// StepEvidence is what Rank needs to diagnose one failing step: the
// failing step itself, and (if available) the last known-good step, so
// detectors can score by *relative* change rather than an arbitrary
// absolute threshold. Baseline's zero value (WallSeconds == 0) means
// "no baseline available" — detectors degrade to an absolute-magnitude
// heuristic in that case rather than failing outright.
type StepEvidence struct {
	Baseline StepMetrics
	Failing  StepMetrics
}

func (e StepEvidence) hasBaseline() bool { return e.Baseline.WallSeconds > 0 }

// Candidate is one ranked hypothesis about what limited the cluster.
type Candidate struct {
	Name     string
	Score    float64 // higher = more likely; comparable across candidates from the same Rank call, not across runs
	Evidence []string
}

// Detector computes one Candidate's score from StepEvidence. ok is
// false when the detector didn't have enough data to compute anything
// (e.g. the metric it needs wasn't in the snapshot) — that's not an
// error, it's "no evidence either way," and Rank simply excludes it
// rather than assigning a misleading zero score that would rank as
// "definitely not the cause."
type Detector func(ev StepEvidence) (Candidate, bool)

// Rank runs every detector and returns Candidates that had enough data
// to score, sorted highest-score-first.
func Rank(ev StepEvidence, detectors []Detector) []Candidate {
	var candidates []Candidate
	for _, d := range detectors {
		if c, ok := d(ev); ok {
			candidates = append(candidates, c)
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].Score > candidates[j].Score })
	return candidates
}

// deltaCounter returns the increase in a counter/gauge metric's total
// value between before and after, for the given target. ok is false if
// the target or metric is missing from either snapshot.
func deltaCounter(m StepMetrics, target, metric string) (delta float64, ok bool) {
	before, ok1 := m.ServerBefore[target]
	after, ok2 := m.ServerAfter[target]
	if !ok1 || !ok2 {
		return 0, false
	}
	bf, ok3 := before.Families[metric]
	af, ok4 := after.Families[metric]
	if !ok3 || !ok4 {
		return 0, false
	}
	return af.SumValue() - bf.SumValue(), true
}

// deltaHistogramAvg returns the average value (sum/count) of a
// histogram metric's *increase* between before and after — the average
// latency of operations that happened *during* the window, not the
// average over all time.
func deltaHistogramAvg(m StepMetrics, target, metric string) (avg float64, ok bool) {
	before, ok1 := m.ServerBefore[target]
	after, ok2 := m.ServerAfter[target]
	if !ok1 || !ok2 {
		return 0, false
	}
	bf, ok3 := before.Families[metric]
	af, ok4 := after.Families[metric]
	if !ok3 || !ok4 {
		return 0, false
	}
	bSum, bCount := bf.SumHistogram()
	aSum, aCount := af.SumHistogram()
	deltaCount := aCount - bCount
	if deltaCount == 0 {
		return 0, false
	}
	return (aSum - bSum) / float64(deltaCount), true
}

// CPUSaturationDetector scores based on process CPU utilization
// (process_cpu_seconds_total delta / wall-clock elapsed / cores) for
// the given scrape target during the failing step, compared against
// the baseline step's utilization if available. cores should be the
// target process's actual CPU limit/request (e.g. from its Kubernetes
// resource limits) — there's no way to infer this from the metric
// itself, so it must be supplied.
func CPUSaturationDetector(name, target string, cores float64) Detector {
	return func(ev StepEvidence) (Candidate, bool) {
		delta, ok := deltaCounter(ev.Failing, target, MetricProcessCPUSeconds)
		if !ok || ev.Failing.WallSeconds <= 0 || cores <= 0 {
			return Candidate{}, false
		}
		utilPct := 100 * delta / ev.Failing.WallSeconds / cores

		baseUtilPct := 0.0
		if ev.hasBaseline() {
			if baseDelta, ok := deltaCounter(ev.Baseline, target, MetricProcessCPUSeconds); ok && ev.Baseline.WallSeconds > 0 {
				baseUtilPct = 100 * baseDelta / ev.Baseline.WallSeconds / cores
			}
		}

		return Candidate{
			Name:  name,
			Score: utilPct,
			Evidence: []string{fmt.Sprintf(
				"%s process CPU utilization %.1f%% during the failing step (baseline %.1f%%), from %s",
				target, utilPct, baseUtilPct, MetricProcessCPUSeconds,
			)},
		}, true
	}
}

// BackendLatencyDetector scores based on how much backend read/write
// latency increased relative to the baseline step. Score is the
// percentage increase (e.g. a 5x slowdown scores 400); with no
// baseline, falls back to scoring directly on absolute latency in
// milliseconds, which is a weaker but still informative signal.
func BackendLatencyDetector(name, target string) Detector {
	metrics := []string{MetricBackendReadSeconds, MetricBackendWriteSeconds}
	return func(ev StepEvidence) (Candidate, bool) {
		failAvg, failOK := combinedHistogramAvg(ev.Failing, target, metrics)
		if !failOK {
			return Candidate{}, false
		}

		var score float64
		var baseAvg float64
		var baseOK bool
		if ev.hasBaseline() {
			baseAvg, baseOK = combinedHistogramAvg(ev.Baseline, target, metrics)
		}
		switch {
		case baseOK && baseAvg > 0:
			score = 100 * (failAvg/baseAvg - 1)
			if score < 0 {
				score = 0
			}
		default:
			// No usable baseline: fall back to absolute magnitude
			// (milliseconds) as a weaker signal.
			score = failAvg * 1000
		}

		return Candidate{
			Name:  name,
			Score: score,
			Evidence: []string{fmt.Sprintf(
				"%s backend read/write avg latency %.1fms during the failing step vs %.1fms baseline, from %v",
				target, failAvg*1000, baseAvg*1000, metrics,
			)},
		}, true
	}
}

func combinedHistogramAvg(m StepMetrics, target string, metrics []string) (avg float64, ok bool) {
	before, ok1 := m.ServerBefore[target]
	after, ok2 := m.ServerAfter[target]
	if !ok1 || !ok2 {
		return 0, false
	}
	var sumDelta float64
	var countDelta uint64
	var found bool
	for _, name := range metrics {
		bf, ok3 := before.Families[name]
		af, ok4 := after.Families[name]
		if !ok3 || !ok4 {
			continue
		}
		found = true
		bSum, bCount := bf.SumHistogram()
		aSum, aCount := af.SumHistogram()
		sumDelta += aSum - bSum
		countDelta += aCount - bCount
	}
	if !found || countDelta == 0 {
		return 0, false
	}
	return sumDelta / float64(countDelta), true
}

// RateLimiterDetector scores based purely on the generator's own
// outcome classification — Teleport's per-IP web-login limiter (and
// lib/limiter generally) exposes no Prometheus metric at all (verified
// against the pinned source, not assumed), so this is the only
// available signal for this candidate, by design rather than omission.
func RateLimiterDetector(name string) Detector {
	return func(ev StepEvidence) (Candidate, bool) {
		snap := ev.Failing.Generator
		if snap.Total == 0 {
			return Candidate{}, false
		}
		pct := 100 * float64(snap.Outcomes[scenario.RateLimited]) / float64(snap.Total)
		return Candidate{
			Name:  name,
			Score: pct,
			Evidence: []string{fmt.Sprintf(
				"%.1f%% of requests classified rate-limited during the failing step (%d/%d) — no server-side metric exists for this limiter, so this is generator-observed only",
				pct, snap.Outcomes[scenario.RateLimited], snap.Total,
			)},
		}, true
	}
}

// GoroutineGrowthDetector scores based on goroutine count growth on the
// given target, relative to baseline — a simple proxy for a leak or
// unbounded queueing, per domain constraint #7 / the "Attribution"
// candidate list's "Go heap growth or goroutine leak."
func GoroutineGrowthDetector(name, target string) Detector {
	return func(ev StepEvidence) (Candidate, bool) {
		after, ok := ev.Failing.ServerAfter[target]
		if !ok {
			return Candidate{}, false
		}
		fam, ok := after.Families[MetricGoGoroutines]
		if !ok {
			return Candidate{}, false
		}
		current := fam.SumValue()

		baseline := current
		if ev.hasBaseline() {
			if bAfter, ok := ev.Baseline.ServerAfter[target]; ok {
				if bFam, ok := bAfter.Families[MetricGoGoroutines]; ok {
					baseline = bFam.SumValue()
				}
			}
		}
		var score float64
		if baseline > 0 {
			score = 100 * (current/baseline - 1)
		}
		if score < 0 {
			score = 0
		}
		return Candidate{
			Name:  name,
			Score: score,
			Evidence: []string{fmt.Sprintf(
				"%s goroutine count %.0f during the failing step vs %.0f baseline, from %s",
				target, current, baseline, MetricGoGoroutines,
			)},
		}, true
	}
}

// CacheStalenessDetector scores based on the cache's own stale-events
// counter growth. Its Help text in the actual source is explicit that
// this indicates a degraded backend, making it useful corroborating
// evidence alongside BackendLatencyDetector, not just a fallback.
func CacheStalenessDetector(name, target string) Detector {
	return func(ev StepEvidence) (Candidate, bool) {
		staleDelta, ok := deltaCounter(ev.Failing, target, MetricCacheStaleEvents)
		if !ok {
			return Candidate{}, false
		}
		totalDelta, ok := deltaCounter(ev.Failing, target, MetricCacheEvents)
		if !ok || totalDelta == 0 {
			return Candidate{}, false
		}
		pct := 100 * staleDelta / totalDelta
		return Candidate{
			Name:  name,
			Score: pct,
			Evidence: []string{fmt.Sprintf(
				"%s cache stale-event rate %.1f%% during the failing step (%s/%s) — its own metric Help text: \"a high percentage of stale events can indicate a degraded backend\"",
				target, pct, MetricCacheStaleEvents, MetricCacheEvents,
			)},
		}, true
	}
}
