package attrib

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildGrafanaDashboard_OnlyIncludesPresentMetrics(t *testing.T) {
	snap := &Snapshot{URL: "https://auth:3000/metrics", Families: map[string]*MetricFamily{
		MetricProcessCPUSeconds: counterFamily(0),
		MetricGoGoroutines:      counterFamily(0),
		// heap, backend, cache, gRPC all absent.
	}}

	raw, warnings, err := BuildGrafanaDashboard("auth", snap)
	if err != nil {
		t.Fatalf("BuildGrafanaDashboard: %v", err)
	}

	var dash grafanaDashboard
	if err := json.Unmarshal(raw, &dash); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(dash.Panels) != 2 {
		t.Fatalf("got %d panels, want 2 (CPU + goroutines), dashboard=%s", len(dash.Panels), raw)
	}
	if len(warnings) != 4 {
		t.Errorf("got %d warnings, want 4 (heap, backend, cache, gRPC skipped), got %v", len(warnings), warnings)
	}

	for _, p := range dash.Panels {
		if strings.Contains(p.Targets[0].Expr, MetricBackendReadSeconds) {
			t.Errorf("panel %q references a metric that wasn't in the snapshot", p.Title)
		}
	}
}

func TestBuildGrafanaDashboard_PanelsUseRealMetricNames(t *testing.T) {
	snap := &Snapshot{URL: "https://auth:3000/metrics", Families: map[string]*MetricFamily{
		MetricProcessCPUSeconds: counterFamily(0),
	}}

	raw, _, err := BuildGrafanaDashboard("auth", snap)
	if err != nil {
		t.Fatalf("BuildGrafanaDashboard: %v", err)
	}
	if !strings.Contains(string(raw), MetricProcessCPUSeconds) {
		t.Errorf("dashboard JSON doesn't reference %s:\n%s", MetricProcessCPUSeconds, raw)
	}
}

func TestBuildGrafanaDashboard_EmptySnapshotProducesNoPanels(t *testing.T) {
	snap := &Snapshot{URL: "https://auth:3000/metrics", Families: map[string]*MetricFamily{}}

	raw, warnings, err := BuildGrafanaDashboard("auth", snap)
	if err != nil {
		t.Fatalf("BuildGrafanaDashboard: %v", err)
	}
	var dash grafanaDashboard
	if err := json.Unmarshal(raw, &dash); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}
	if len(dash.Panels) != 0 {
		t.Errorf("expected 0 panels for an empty snapshot, got %d", len(dash.Panels))
	}
	if len(warnings) != len(panelSpecs("auth")) {
		t.Errorf("expected a warning for every candidate panel (%d), got %d", len(panelSpecs("auth")), len(warnings))
	}
}

func TestBuildGrafanaDashboard_GridPositionsDontOverlap(t *testing.T) {
	families := map[string]*MetricFamily{}
	for _, spec := range panelSpecs("auth") {
		for _, m := range spec.metrics {
			families[m] = counterFamily(0)
		}
	}
	snap := &Snapshot{URL: "https://auth:3000/metrics", Families: families}

	raw, _, err := BuildGrafanaDashboard("auth", snap)
	if err != nil {
		t.Fatalf("BuildGrafanaDashboard: %v", err)
	}
	var dash grafanaDashboard
	if err := json.Unmarshal(raw, &dash); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	seen := make(map[[2]int]bool)
	for _, p := range dash.Panels {
		key := [2]int{p.GridPos.X, p.GridPos.Y}
		if seen[key] {
			t.Errorf("panel %q collides with another panel at gridPos %v", p.Title, key)
		}
		seen[key] = true
	}
}
