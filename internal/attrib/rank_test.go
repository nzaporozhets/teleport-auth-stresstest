package attrib

import (
	"testing"

	"teleport-auth-stress/internal/collect"
	"teleport-auth-stress/internal/scenario"
)

func counterFamily(value float64) *MetricFamily {
	return &MetricFamily{Type: "counter", Samples: []Sample{{Value: value}}}
}

func histogramFamily(sum float64, count uint64) *MetricFamily {
	return &MetricFamily{Type: "histogram", Samples: []Sample{{Sum: sum, Count: count}}}
}

func snap(families map[string]*MetricFamily) *Snapshot {
	return &Snapshot{Target: "auth", Families: families}
}

// genSnapshot builds a minimal collect.Snapshot with the given total
// count and rate-limited count (rest counted success), for
// RateLimiterDetector's generator-side-only evidence.
func genSnapshot(total, rateLimited int64) collect.Snapshot {
	return collect.Snapshot{
		Total: total,
		Outcomes: map[scenario.Outcome]int64{
			scenario.Success:     total - rateLimited,
			scenario.RateLimited: rateLimited,
		},
	}
}

func allDetectors() []Detector {
	return []Detector{
		CPUSaturationDetector("auth-cpu-saturation", "auth", 1),
		BackendLatencyDetector("backend-latency", "auth"),
		RateLimiterDetector("rate-limiter-engaged"),
		GoroutineGrowthDetector("goroutine-growth", "auth"),
		CacheStalenessDetector("cache-staleness", "auth"),
	}
}

// TestRank_CPULimitedAuth is the first of M6's three required synthetic
// bottleneck scenarios: an auth process pinned near its CPU limit,
// backend and rate limiter both healthy.
func TestRank_CPULimitedAuth(t *testing.T) {
	baseline := StepMetrics{
		ServerBefore: map[string]*Snapshot{"auth": snap(map[string]*MetricFamily{
			MetricProcessCPUSeconds:  counterFamily(0),
			MetricBackendReadSeconds: histogramFamily(0, 0),
			MetricGoGoroutines:       counterFamily(200),
		})},
		ServerAfter: map[string]*Snapshot{"auth": snap(map[string]*MetricFamily{
			MetricProcessCPUSeconds:  counterFamily(2), // 2s CPU / 60s wall / 1 core = 3.3%
			MetricBackendReadSeconds: histogramFamily(0.5, 100),
			MetricGoGoroutines:       counterFamily(210),
		})},
		Generator:   genSnapshot(100, 0),
		WallSeconds: 60,
	}
	failing := StepMetrics{
		ServerBefore: map[string]*Snapshot{"auth": snap(map[string]*MetricFamily{
			MetricProcessCPUSeconds:  counterFamily(0),
			MetricBackendReadSeconds: histogramFamily(0, 0),
			MetricGoGoroutines:       counterFamily(210),
		})},
		ServerAfter: map[string]*Snapshot{"auth": snap(map[string]*MetricFamily{
			MetricProcessCPUSeconds:  counterFamily(55),         // 55s CPU / 60s wall / 1 core = 91.7%
			MetricBackendReadSeconds: histogramFamily(0.6, 100), // latency unchanged
			MetricGoGoroutines:       counterFamily(230),
		})},
		Generator:   genSnapshot(100, 2),
		WallSeconds: 60,
	}

	ranked := Rank(StepEvidence{Baseline: baseline, Failing: failing}, allDetectors())
	if len(ranked) == 0 {
		t.Fatal("expected at least one candidate")
	}
	if ranked[0].Name != "auth-cpu-saturation" {
		t.Fatalf("top candidate = %q, want auth-cpu-saturation; full ranking: %+v", ranked[0].Name, ranked)
	}
}

// TestRank_SlowedBackend is the second required scenario: an
// artificially slowed backend, auth CPU and rate limiter both healthy.
func TestRank_SlowedBackend(t *testing.T) {
	baseline := StepMetrics{
		ServerBefore: map[string]*Snapshot{"auth": snap(map[string]*MetricFamily{
			MetricProcessCPUSeconds:  counterFamily(0),
			MetricBackendReadSeconds: histogramFamily(0, 0),
			MetricCacheEvents:        counterFamily(0),
			MetricCacheStaleEvents:   counterFamily(0),
			MetricGoGoroutines:       counterFamily(200),
		})},
		ServerAfter: map[string]*Snapshot{"auth": snap(map[string]*MetricFamily{
			MetricProcessCPUSeconds:  counterFamily(3),          // 5% util
			MetricBackendReadSeconds: histogramFamily(0.5, 100), // 5ms avg
			MetricCacheEvents:        counterFamily(100),
			MetricCacheStaleEvents:   counterFamily(1), // 1% stale
			MetricGoGoroutines:       counterFamily(205),
		})},
		Generator:   genSnapshot(100, 0),
		WallSeconds: 60,
	}
	failing := StepMetrics{
		ServerBefore: map[string]*Snapshot{"auth": snap(map[string]*MetricFamily{
			MetricProcessCPUSeconds:  counterFamily(0),
			MetricBackendReadSeconds: histogramFamily(0, 0),
			MetricCacheEvents:        counterFamily(0),
			MetricCacheStaleEvents:   counterFamily(0),
			MetricGoGoroutines:       counterFamily(205),
		})},
		ServerAfter: map[string]*Snapshot{"auth": snap(map[string]*MetricFamily{
			MetricProcessCPUSeconds:  counterFamily(6),         // still just 10% util, not saturated
			MetricBackendReadSeconds: histogramFamily(20, 100), // 200ms avg: 40x baseline
			MetricCacheEvents:        counterFamily(100),
			MetricCacheStaleEvents:   counterFamily(15),  // stale rate jumped
			MetricGoGoroutines:       counterFamily(260), // some growth from queueing, but not dominant
		})},
		Generator:   genSnapshot(100, 3),
		WallSeconds: 60,
	}

	ranked := Rank(StepEvidence{Baseline: baseline, Failing: failing}, allDetectors())
	if len(ranked) == 0 {
		t.Fatal("expected at least one candidate")
	}
	if ranked[0].Name != "backend-latency" {
		t.Fatalf("top candidate = %q, want backend-latency; full ranking: %+v", ranked[0].Name, ranked)
	}
}

// TestRank_EngagedRateLimiter is the third required scenario: the
// per-IP login rate limiter engaging. No server metric exists for this
// (verified against source, not assumed) — the signal is entirely
// generator-side, and this test also proves that absence of a metric
// doesn't prevent this candidate from ranking correctly.
func TestRank_EngagedRateLimiter(t *testing.T) {
	baseline := StepMetrics{
		ServerBefore: map[string]*Snapshot{"auth": snap(map[string]*MetricFamily{
			MetricProcessCPUSeconds:  counterFamily(0),
			MetricBackendReadSeconds: histogramFamily(0, 0),
			MetricGoGoroutines:       counterFamily(200),
		})},
		ServerAfter: map[string]*Snapshot{"auth": snap(map[string]*MetricFamily{
			MetricProcessCPUSeconds:  counterFamily(2),
			MetricBackendReadSeconds: histogramFamily(0.5, 100),
			MetricGoGoroutines:       counterFamily(205),
		})},
		Generator:   genSnapshot(100, 0),
		WallSeconds: 60,
	}
	failing := StepMetrics{
		ServerBefore: map[string]*Snapshot{"auth": snap(map[string]*MetricFamily{
			MetricProcessCPUSeconds:  counterFamily(0),
			MetricBackendReadSeconds: histogramFamily(0, 0),
			MetricGoGoroutines:       counterFamily(205),
		})},
		ServerAfter: map[string]*Snapshot{"auth": snap(map[string]*MetricFamily{
			MetricProcessCPUSeconds:  counterFamily(3),           // still low util
			MetricBackendReadSeconds: histogramFamily(0.55, 100), // latency basically unchanged
			MetricGoGoroutines:       counterFamily(208),
		})},
		Generator:   genSnapshot(100, 84), // 84% rate-limited, matching the live-cluster finding
		WallSeconds: 60,
	}

	ranked := Rank(StepEvidence{Baseline: baseline, Failing: failing}, allDetectors())
	if len(ranked) == 0 {
		t.Fatal("expected at least one candidate")
	}
	if ranked[0].Name != "rate-limiter-engaged" {
		t.Fatalf("top candidate = %q, want rate-limiter-engaged; full ranking: %+v", ranked[0].Name, ranked)
	}
}

func TestRank_ExcludesDetectorsWithNoData(t *testing.T) {
	ev := StepEvidence{
		Failing: StepMetrics{
			Generator:   genSnapshot(10, 0),
			WallSeconds: 10,
			// No ServerBefore/ServerAfter at all: every metric-based
			// detector should decline to score, leaving only the
			// generator-side rate limiter detector.
		},
	}
	ranked := Rank(ev, allDetectors())
	if len(ranked) != 1 || ranked[0].Name != "rate-limiter-engaged" {
		t.Fatalf("expected only rate-limiter-engaged (the one detector needing no server metrics), got %+v", ranked)
	}
}

func TestRank_SortsDescending(t *testing.T) {
	detectors := []Detector{
		func(StepEvidence) (Candidate, bool) { return Candidate{Name: "low", Score: 1}, true },
		func(StepEvidence) (Candidate, bool) { return Candidate{Name: "high", Score: 100}, true },
		func(StepEvidence) (Candidate, bool) { return Candidate{Name: "mid", Score: 50}, true },
	}
	ranked := Rank(StepEvidence{}, detectors)
	if len(ranked) != 3 || ranked[0].Name != "high" || ranked[1].Name != "mid" || ranked[2].Name != "low" {
		t.Fatalf("Rank did not sort descending by score: %+v", ranked)
	}
}

func TestStepEvidence_NoBaselineDoesNotPanic(t *testing.T) {
	failing := StepMetrics{
		ServerBefore: map[string]*Snapshot{"auth": snap(map[string]*MetricFamily{
			MetricProcessCPUSeconds: counterFamily(0),
		})},
		ServerAfter: map[string]*Snapshot{"auth": snap(map[string]*MetricFamily{
			MetricProcessCPUSeconds: counterFamily(30),
		})},
		Generator:   genSnapshot(10, 0),
		WallSeconds: 60,
	}
	// Baseline is the zero value (no baseline available).
	ranked := Rank(StepEvidence{Failing: failing}, allDetectors())
	found := false
	for _, c := range ranked {
		if c.Name == "auth-cpu-saturation" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected auth-cpu-saturation to still score without a baseline, got %+v", ranked)
	}
}
