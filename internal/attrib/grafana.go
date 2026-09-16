package attrib

import (
	"encoding/json"
	"fmt"
)

// panelSpec is one candidate Grafana panel: a PromQL query built from a
// real metric name, included only if that name is actually present in
// the live snapshot the dashboard is generated from (instructions.md:
// "build ... the Grafana dashboard from names that actually exist in
// the target version").
type panelSpec struct {
	title      string
	unit       string
	metrics    []string // every one of these must be present
	requireAny bool     // if true, at least one (not all) must be present
	expr       func() string
}

func panelSpecs(target string) []panelSpec {
	return []panelSpec{
		{
			title:   fmt.Sprintf("%s: CPU utilization", target),
			unit:    "percentunit",
			metrics: []string{MetricProcessCPUSeconds},
			expr:    func() string { return fmt.Sprintf(`rate(%s{job="%s"}[1m])`, MetricProcessCPUSeconds, target) },
		},
		{
			title:   fmt.Sprintf("%s: goroutines", target),
			unit:    "short",
			metrics: []string{MetricGoGoroutines},
			expr:    func() string { return fmt.Sprintf(`%s{job="%s"}`, MetricGoGoroutines, target) },
		},
		{
			title:   fmt.Sprintf("%s: heap in use", target),
			unit:    "bytes",
			metrics: []string{MetricGoHeapAllocBytes},
			expr:    func() string { return fmt.Sprintf(`%s{job="%s"}`, MetricGoHeapAllocBytes, target) },
		},
		{
			title:      fmt.Sprintf("%s: backend read/write avg latency", target),
			unit:       "s",
			metrics:    []string{MetricBackendReadSeconds, MetricBackendWriteSeconds},
			requireAny: true,
			expr: func() string {
				return fmt.Sprintf(
					`(rate(%s_sum{job="%s"}[1m]) + rate(%s_sum{job="%s"}[1m])) / (rate(%s_count{job="%s"}[1m]) + rate(%s_count{job="%s"}[1m]))`,
					MetricBackendReadSeconds, target, MetricBackendWriteSeconds, target,
					MetricBackendReadSeconds, target, MetricBackendWriteSeconds, target,
				)
			},
		},
		{
			title:   fmt.Sprintf("%s: cache stale-event rate", target),
			unit:    "percentunit",
			metrics: []string{MetricCacheEvents, MetricCacheStaleEvents},
			expr: func() string {
				return fmt.Sprintf(`rate(%s{job="%s"}[5m]) / rate(%s{job="%s"}[5m])`,
					MetricCacheStaleEvents, target, MetricCacheEvents, target)
			},
		},
		{
			title:   fmt.Sprintf("%s: gRPC error rate", target),
			unit:    "percentunit",
			metrics: []string{MetricGRPCServerHandledTotal},
			expr: func() string {
				return fmt.Sprintf(`sum(rate(%s{job="%s",grpc_code!="OK"}[1m])) / sum(rate(%s{job="%s"}[1m]))`,
					MetricGRPCServerHandledTotal, target, MetricGRPCServerHandledTotal, target)
			},
		},
	}
}

// grafanaPanel and grafanaDashboard are a minimal but valid subset of
// Grafana's dashboard JSON schema — enough for each panel to render as
// a time series graph with the right PromQL query and unit; Grafana
// fills in sensible defaults for anything omitted on import.
type grafanaTarget struct {
	Expr       string            `json:"expr"`
	RefID      string            `json:"refId"`
	Datasource map[string]string `json:"datasource"`
}

type grafanaGridPos struct {
	X int `json:"x"`
	Y int `json:"y"`
	W int `json:"w"`
	H int `json:"h"`
}

type grafanaFieldConfig struct {
	Defaults map[string]string `json:"defaults"`
}

type grafanaPanel struct {
	ID          int                `json:"id"`
	Title       string             `json:"title"`
	Type        string             `json:"type"`
	GridPos     grafanaGridPos     `json:"gridPos"`
	FieldConfig grafanaFieldConfig `json:"fieldConfig"`
	Targets     []grafanaTarget    `json:"targets"`
}

type grafanaDashboard struct {
	Title         string         `json:"title"`
	SchemaVersion int            `json:"schemaVersion"`
	Panels        []grafanaPanel `json:"panels"`
}

// BuildGrafanaDashboard generates a Grafana dashboard (as JSON) for
// target, containing one panel per candidate signal whose metric(s) are
// actually present in snap — never a panel referencing a metric name
// this cluster's version doesn't have. Returns a warning per skipped
// panel, same "fail loudly" pattern as BuildDetectors.
func BuildGrafanaDashboard(target string, snap *Snapshot) (dashboardJSON []byte, warnings []string, err error) {
	dash := grafanaDashboard{
		Title:         fmt.Sprintf("teleport-auth-stress: %s", target),
		SchemaVersion: 39,
	}

	const cols = 2
	const panelW, panelH = 12, 8
	id := 1

	for _, spec := range panelSpecs(target) {
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
				"skipping Grafana panel %q for target %q: missing metric(s) %v in the live snapshot from %s",
				spec.title, target, missing, snap.URL,
			))
			continue
		}

		row := (id - 1) / cols
		col := (id - 1) % cols
		dash.Panels = append(dash.Panels, grafanaPanel{
			ID:      id,
			Title:   spec.title,
			Type:    "timeseries",
			GridPos: grafanaGridPos{X: col * panelW, Y: row * panelH, W: panelW, H: panelH},
			FieldConfig: grafanaFieldConfig{
				Defaults: map[string]string{"unit": spec.unit},
			},
			Targets: []grafanaTarget{{
				Expr:       spec.expr(),
				RefID:      "A",
				Datasource: map[string]string{"type": "prometheus"},
			}},
		})
		id++
	}

	dashboardJSON, err = json.MarshalIndent(dash, "", "  ")
	if err != nil {
		return nil, warnings, fmt.Errorf("marshalling dashboard: %w", err)
	}
	return dashboardJSON, warnings, nil
}
