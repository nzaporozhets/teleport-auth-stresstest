package attrib

import (
	"strings"
	"testing"
)

func TestBuildDetectors_AllMetricsPresent(t *testing.T) {
	full := &Snapshot{URL: "https://auth:3000/metrics", Families: map[string]*MetricFamily{
		MetricProcessCPUSeconds:  counterFamily(0),
		MetricBackendReadSeconds: histogramFamily(0, 0),
		MetricGoGoroutines:       counterFamily(0),
		MetricCacheEvents:        counterFamily(0),
		MetricCacheStaleEvents:   counterFamily(0),
	}}

	detectors, warnings := BuildDetectors("auth", full, 1)
	if len(warnings) != 0 {
		t.Errorf("expected no warnings when every metric is present, got %v", warnings)
	}
	if len(detectors) != 4 {
		t.Errorf("got %d detectors, want 4 (RateLimiterDetector is the caller's responsibility, not BuildDetectors')", len(detectors))
	}
}

func TestBuildDetectors_MissingMetricsWarnLoudlyAndSkip(t *testing.T) {
	sparse := &Snapshot{URL: "https://auth:3000/metrics", Families: map[string]*MetricFamily{
		MetricGoGoroutines: counterFamily(0),
		// process_cpu_seconds_total, backend_*, cache_* all absent.
	}}

	detectors, warnings := BuildDetectors("auth", sparse, 1)

	// Only goroutine-growth (its one required metric is present) should
	// build; cpu-saturation, backend-latency, and cache-staleness all
	// lack their metric(s).
	if len(detectors) != 1 {
		t.Fatalf("got %d detectors, want 1 (auth-goroutine-growth), warnings=%v", len(detectors), warnings)
	}
	if len(warnings) != 3 {
		t.Fatalf("got %d warnings, want 3 (cpu-saturation, backend-latency, cache-staleness skipped), warnings=%v", len(warnings), warnings)
	}
}

func TestBuildDetectors_WarningNamesTheMissingMetric(t *testing.T) {
	empty := &Snapshot{URL: "https://auth:3000/metrics", Families: map[string]*MetricFamily{}}
	_, warnings := BuildDetectors("auth", empty, 1)

	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, MetricProcessCPUSeconds) {
		t.Errorf("expected a warning naming %q, got: %s", MetricProcessCPUSeconds, joined)
	}
	if !strings.Contains(joined, "auth-cpu-saturation") {
		t.Errorf("expected a warning naming the skipped candidate auth-cpu-saturation, got: %s", joined)
	}
}

func TestBuildDetectors_BackendLatencyRequiresOnlyOneOfReadOrWrite(t *testing.T) {
	writeOnly := &Snapshot{URL: "https://auth:3000/metrics", Families: map[string]*MetricFamily{
		MetricBackendWriteSeconds: histogramFamily(0, 0),
	}}
	_, warnings := BuildDetectors("auth", writeOnly, 1)

	for _, w := range warnings {
		if strings.Contains(w, "backend-latency") {
			t.Errorf("backend-latency should not be skipped when only write latency is present, got warning: %s", w)
		}
	}
}
