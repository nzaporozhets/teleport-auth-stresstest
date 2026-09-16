// Attribution wiring (M6): scrapes observability.scrape targets to
// build detectors/Grafana dashboards at startup, then correlates
// before/after metric snapshots against each failing step to produce a
// ranked list of candidate limiting resources. Scraping/parsing
// failures here are logged and skipped, never fatal to the run —
// attribution is a diagnostic aid, not part of the load test's own
// correctness (unlike, say, the guardrail checks).
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"teleport-auth-stress/internal/attrib"
	"teleport-auth-stress/internal/config"
	"teleport-auth-stress/internal/ramp"
)

// newMetricsClient builds the HTTP client used for scraping /metrics
// and capturing pprof profiles — a separate client from any scenario
// client, since these are cluster-internal diagnostic endpoints
// (typically a Teleport diag_addr/metrics_service), not the public
// proxy the scenarios talk to.
func newMetricsClient(insecureSkipVerify bool) *http.Client {
	return &http.Client{
		Timeout: 15 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: insecureSkipVerify}, //nolint:gosec // opt-in via config, for disposable test clusters only
		},
	}
}

// attribSetup is everything computed once at startup from the live
// /metrics snapshots, before the ramp begins.
type attribSetup struct {
	detectors []attrib.Detector
	snapshots map[string]*attrib.Snapshot // by target name, most recent scrape
}

// setupAttribution snapshots every configured scrape target once,
// builds the detector list and Grafana dashboards from whatever metrics
// actually exist — instructions.md: "snapshot the live /metrics output
// ... and build the scrape list and Grafana dashboard from names that
// actually exist ... fail loudly with the list of missing names" — and
// writes the dashboards to cfg.Report.OutputDir.
func setupAttribution(ctx context.Context, client *http.Client, cfg *config.Config) *attribSetup {
	setup := &attribSetup{snapshots: make(map[string]*attrib.Snapshot)}
	// Needs no server-side metric at all — always on, added once
	// regardless of how many scrape targets exist (BuildDetectors is
	// per-target and deliberately does not include this itself).
	setup.detectors = append(setup.detectors, attrib.RateLimiterDetector("rate-limiter-engaged"))

	for _, target := range cfg.Observability.Scrape {
		snap, err := attrib.Fetch(ctx, client, target.Name, target.URL)
		if err != nil {
			slog.Warn("attribution: could not scrape target; its detectors and dashboard are skipped for this run", "target", target.Name, "url", target.URL, "error", err)
			continue
		}
		setup.snapshots[target.Name] = snap

		cores := target.Cores
		if cores <= 0 {
			cores = 1
		}
		detectors, warnings := attrib.BuildDetectors(target.Name, snap, cores)
		for _, w := range warnings {
			slog.Warn("attribution: " + w)
		}
		setup.detectors = append(setup.detectors, detectors...)

		dashboardJSON, dashWarnings, err := attrib.BuildGrafanaDashboard(target.Name, snap)
		for _, w := range dashWarnings {
			slog.Warn("attribution: " + w)
		}
		if err != nil {
			slog.Warn("attribution: building Grafana dashboard failed", "target", target.Name, "error", err)
			continue
		}
		dashPath := filepath.Join(cfg.Report.OutputDir, fmt.Sprintf("grafana-%s-dashboard.json", target.Name))
		if err := writeFileMkdir(dashPath, dashboardJSON); err != nil {
			slog.Warn("attribution: writing Grafana dashboard failed", "target", target.Name, "path", dashPath, "error", err)
		} else {
			slog.Info("attribution: wrote Grafana dashboard", "target", target.Name, "path", dashPath)
		}
	}
	return setup
}

func writeFileMkdir(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o644)
}

func findScrapeTarget(targets []config.ScrapeTarget, name string) *config.ScrapeTarget {
	for i := range targets {
		if targets[i].Name == name {
			return &targets[i]
		}
	}
	return nil
}

// stepAttributor tracks state across ramp steps: it scrapes "after"
// snapshots at each step's end (reusing the previous step's "after" as
// this step's "before" — the gap between them is the settle/discard
// window anyway), ranks failing steps against the last passing step's
// baseline, and triggers per-step pprof capture.
type stepAttributor struct {
	client    *http.Client
	cfg       *config.Config
	detectors []attrib.Detector

	mu        sync.Mutex
	prev      map[string]*attrib.Snapshot
	prevTime  time.Time
	baseline  *attrib.StepMetrics
	ranked    map[int][]attrib.Candidate
	nextIndex int
}

func newStepAttributor(client *http.Client, cfg *config.Config, setup *attribSetup) *stepAttributor {
	return &stepAttributor{
		client:    client,
		cfg:       cfg,
		detectors: setup.detectors,
		prev:      setup.snapshots,
		prevTime:  time.Now(),
		ranked:    make(map[int][]attrib.Candidate),
	}
}

// onStepStart fires right when a step's measured window begins. Its
// only job is kicking off a concurrent pprof capture "at steady state"
// (instructions.md) — metrics snapshots are taken at each step's *end*
// instead (in onStep), since that's cheap and doesn't need this hook.
func (a *stepAttributor) onStepStart(float64) {
	if !a.cfg.Observability.Pprof.Enabled || !a.cfg.Observability.Pprof.CaptureAtEachStep {
		return
	}
	a.mu.Lock()
	stepIdx := a.nextIndex
	a.mu.Unlock()

	duration := 30 * time.Second
	if a.cfg.Load.Ramp.StepDuration < duration {
		duration = a.cfg.Load.Ramp.StepDuration
	}
	for _, targetName := range a.cfg.Observability.Pprof.Targets {
		target := findScrapeTarget(a.cfg.Observability.Scrape, targetName)
		if target == nil {
			slog.Warn("attribution: pprof target not found in observability.scrape, skipping", "target", targetName)
			continue
		}
		url := attrib.PProfURL(target.URL)
		outPath := filepath.Join(a.cfg.Report.OutputDir, fmt.Sprintf("pprof-%s-step%d.pb.gz", targetName, stepIdx))
		go func(url, outPath, targetName string) {
			if err := attrib.CaptureCPUProfile(context.Background(), a.client, url, duration, outPath); err != nil {
				slog.Warn("attribution: pprof capture failed", "target", targetName, "error", err)
				return
			}
			slog.Info("attribution: captured pprof profile", "target", targetName, "path", outPath)
		}(url, outPath, targetName)
	}
}

// onStep fires when a step completes: scrapes "after" snapshots, ranks
// the failing step (if any) against the last passing step's baseline,
// and remembers a passing step as the new baseline for the next one.
func (a *stepAttributor) onStep(ctx context.Context, s ramp.StepReport) {
	a.mu.Lock()
	defer a.mu.Unlock()

	stepIdx := a.nextIndex
	a.nextIndex++

	after := make(map[string]*attrib.Snapshot, len(a.cfg.Observability.Scrape))
	for _, target := range a.cfg.Observability.Scrape {
		snap, err := attrib.Fetch(ctx, a.client, target.Name, target.URL)
		if err != nil {
			slog.Warn("attribution: could not scrape target for step evidence", "target", target.Name, "step", stepIdx, "error", err)
			continue
		}
		after[target.Name] = snap
	}

	metrics := attrib.StepMetrics{
		ServerBefore: a.prev,
		ServerAfter:  after,
		Generator:    s.Snapshot,
		Health:       s.Health,
		WallSeconds:  time.Since(a.prevTime).Seconds(),
	}

	switch {
	case s.Pass:
		a.baseline = &metrics
	case s.GeneratorLimited:
		// Don't attribute a cluster cause when the generator itself is
		// the confound (domain constraint #7) — already surfaced via
		// GeneratorLimited/Health in the report.
	default:
		ev := attrib.StepEvidence{Failing: metrics}
		if a.baseline != nil {
			ev.Baseline = *a.baseline
		}
		a.ranked[stepIdx] = attrib.Rank(ev, a.detectors)
	}

	a.prev = after
	a.prevTime = time.Now()
}

func (a *stepAttributor) rankedFor(stepIdx int) []attrib.Candidate {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ranked[stepIdx]
}
