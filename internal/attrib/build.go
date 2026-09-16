package attrib

import "fmt"

// detectorSpec pairs a detector builder with the metric name(s) it
// needs, so BuildDetectors can decide inclusion generically rather than
// repeating the same "check presence, then build" logic per detector.
type detectorSpec struct {
	name string
	// metrics required for this detector. If requireAny is true, having
	// at least one of these is enough (matches BackendLatencyDetector,
	// which can work off read latency alone, write latency alone, or
	// both); otherwise every listed metric must be present.
	metrics    []string
	requireAny bool
	build      func() Detector
}

func detectorSpecs(target string, cores float64) []detectorSpec {
	return []detectorSpec{
		{
			name:    target + "-cpu-saturation",
			metrics: []string{MetricProcessCPUSeconds},
			build:   func() Detector { return CPUSaturationDetector(target+"-cpu-saturation", target, cores) },
		},
		{
			name:       target + "-backend-latency",
			metrics:    []string{MetricBackendReadSeconds, MetricBackendWriteSeconds},
			requireAny: true,
			build:      func() Detector { return BackendLatencyDetector(target+"-backend-latency", target) },
		},
		{
			name:    target + "-goroutine-growth",
			metrics: []string{MetricGoGoroutines},
			build:   func() Detector { return GoroutineGrowthDetector(target+"-goroutine-growth", target) },
		},
		{
			name:    target + "-cache-staleness",
			metrics: []string{MetricCacheEvents, MetricCacheStaleEvents},
			build:   func() Detector { return CacheStalenessDetector(target+"-cache-staleness", target) },
		},
	}
}

// BuildDetectors checks snap (a live snapshot from target, taken at
// startup) against every candidate detector this package knows how to
// build, and returns the ones whose required metric(s) are actually
// present in this cluster's version, plus one warning string per
// detector that couldn't be built, naming exactly which metric(s) were
// missing — per instructions.md: "fail loudly with the list of missing
// names if an expected signal is absent," rather than silently
// degrading attribution coverage without telling the operator.
//
// RateLimiterDetector is deliberately NOT included here — it needs no
// target-specific server metric at all (verified against source:
// Teleport's rate limiter has no Prometheus instrumentation), so it
// should be added exactly once by the caller regardless of how many
// scrape targets exist, not once per call to BuildDetectors (which
// would duplicate it if called for both "auth" and "proxy").
func BuildDetectors(target string, snap *Snapshot, cores float64) (detectors []Detector, warnings []string) {
	for _, spec := range detectorSpecs(target, cores) {
		present := 0
		var missing []string
		for _, m := range spec.metrics {
			if snap.Has(m) {
				present++
			} else {
				missing = append(missing, m)
			}
		}

		ok := present == len(spec.metrics)
		if spec.requireAny {
			ok = present > 0
		}

		if !ok {
			warnings = append(warnings, fmt.Sprintf(
				"skipping %q detector on target %q: missing metric(s) %v in the live snapshot from %s",
				spec.name, target, missing, snap.URL,
			))
			continue
		}
		detectors = append(detectors, spec.build())
	}
	return detectors, warnings
}
