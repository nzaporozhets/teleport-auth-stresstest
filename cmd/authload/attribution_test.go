package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"teleport-auth-stress/internal/collect"
	"teleport-auth-stress/internal/config"
	"teleport-auth-stress/internal/ramp"
	"teleport-auth-stress/internal/scenario"
)

const fakeMetrics = `# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 5
# TYPE go_goroutines gauge
go_goroutines 100
`

func TestSetupAttribution_DegradesGracefullyOnUnreachableTarget(t *testing.T) {
	cfg := &config.Config{
		Observability: config.Observability{
			Scrape: []config.ScrapeTarget{
				{Name: "auth", URL: "http://127.0.0.1:1/metrics"}, // nothing listens here
			},
		},
	}
	client := newMetricsClient(false)
	setup := setupAttribution(context.Background(), client, cfg)

	// Only RateLimiterDetector, since the target was unreachable.
	if len(setup.detectors) != 1 {
		t.Errorf("got %d detectors, want 1 (rate-limiter-engaged only), setup=%+v", len(setup.detectors), setup)
	}
	if len(setup.snapshots) != 0 {
		t.Errorf("expected no snapshots for an unreachable target, got %v", setup.snapshots)
	}
}

func TestSetupAttribution_BuildsDetectorsAndWritesDashboard(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fakeMetrics)) //nolint:errcheck
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfg := &config.Config{
		Observability: config.Observability{
			Scrape: []config.ScrapeTarget{{Name: "auth", URL: srv.URL}},
		},
		Report: config.Report{OutputDir: dir},
	}
	client := newMetricsClient(false)
	setup := setupAttribution(context.Background(), client, cfg)

	// RateLimiterDetector + goroutine-growth + cpu-saturation (both
	// metrics present in fakeMetrics).
	if len(setup.detectors) != 3 {
		t.Errorf("got %d detectors, want 3, setup=%+v", len(setup.detectors), setup)
	}
	if _, ok := setup.snapshots["auth"]; !ok {
		t.Error("expected a snapshot for target \"auth\"")
	}

	dashPath := filepath.Join(dir, "grafana-auth-dashboard.json")
	data, err := os.ReadFile(dashPath)
	if err != nil {
		t.Fatalf("expected a Grafana dashboard written to %s: %v", dashPath, err)
	}
	if !strings.Contains(string(data), "process_cpu_seconds_total") {
		t.Errorf("dashboard doesn't reference process_cpu_seconds_total:\n%s", data)
	}
}

// TestStepAttributor_WiringEndToEnd proves onStepStart/onStep/rankedFor
// fit together correctly against a real (fake-server) scrape target: a
// passing step becomes the baseline, a later failing step gets ranked
// against it and stored under the right step index, and a
// generator-limited step is deliberately skipped (domain constraint #7
// — no cluster attribution when the generator itself is the confound).
func TestStepAttributor_WiringEndToEnd(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fakeMetrics)) //nolint:errcheck
	}))
	defer srv.Close()

	dir := t.TempDir()
	cfg := &config.Config{
		Observability: config.Observability{
			Scrape: []config.ScrapeTarget{{Name: "auth", URL: srv.URL, Cores: 1}},
		},
		Report: config.Report{OutputDir: dir},
	}
	client := newMetricsClient(false)
	setup := setupAttribution(context.Background(), client, cfg)
	attributor := newStepAttributor(client, cfg, setup)

	gen := func(outcome scenario.Outcome) collect.Snapshot {
		return collect.Snapshot{Total: 10, Outcomes: map[scenario.Outcome]int64{outcome: 10}}
	}

	// Step 0: passes -> becomes baseline, not ranked.
	attributor.onStep(context.Background(), ramp.StepReport{OfferedRPS: 100, Pass: true, Snapshot: gen(scenario.Success)})
	if got := attributor.rankedFor(0); got != nil {
		t.Errorf("a passing step must not be ranked, got %v", got)
	}
	if attributor.baseline == nil {
		t.Error("a passing step must become the new baseline")
	}

	// Step 1: fails, not generator-limited -> ranked (RateLimiterDetector
	// alone is enough to produce at least one candidate).
	attributor.onStep(context.Background(), ramp.StepReport{OfferedRPS: 200, Pass: false, Snapshot: gen(scenario.RateLimited)})
	if got := attributor.rankedFor(1); len(got) == 0 {
		t.Error("a failing, non-generator-limited step should have ranked candidates")
	}

	// Step 2: fails AND generator-limited -> deliberately not ranked.
	attributor.onStep(context.Background(), ramp.StepReport{OfferedRPS: 300, Pass: false, GeneratorLimited: true, Snapshot: gen(scenario.ServerError)})
	if got := attributor.rankedFor(2); got != nil {
		t.Errorf("a generator-limited step must not be ranked (domain constraint #7), got %v", got)
	}
}
