// Package attrib correlates the generator's error/latency timeline
// against server-side signals to rank candidate limiting resources with
// evidence, per instructions.md's "Attribution" section. Metric names
// are never hard-coded from training-data memory: at startup the
// scrape/signal list is built from names that actually exist in a live
// snapshot from the target version, and an expected-but-absent signal
// fails loudly rather than silently querying a name that isn't there.
package attrib

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

// Sample is one label combination's value within a metric family.
// Counter/Gauge/Untyped families use Value; Histogram/Summary families
// use Sum/Count (their per-bucket detail isn't needed for attribution —
// only the aggregate rate/average across a step matters here).
type Sample struct {
	Labels map[string]string
	Value  float64
	Sum    float64
	Count  uint64
}

// MetricFamily is one named metric and every label combination it was
// reported with.
type MetricFamily struct {
	Name    string
	Type    string // "counter", "gauge", "histogram", "summary", "untyped"
	Help    string
	Samples []Sample
}

// Snapshot is everything scraped from one target at one point in time.
type Snapshot struct {
	Target    string // e.g. "auth", matching observability.scrape[].name
	URL       string
	FetchedAt time.Time
	Families  map[string]*MetricFamily
}

// Has reports whether name was present in this snapshot.
func (s *Snapshot) Has(name string) bool {
	_, ok := s.Families[name]
	return ok
}

// Fetch scrapes url (Prometheus text exposition format, exactly what
// promhttp.Handler()/the default registry produce — the same format
// Teleport's own /metrics endpoint uses) and parses it into a Snapshot.
func Fetch(ctx context.Context, client *http.Client, target, url string) (*Snapshot, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("building request for %s: %w", url, err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("scraping %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("scraping %s: unexpected status %d", url, resp.StatusCode)
	}

	// LegacyValidation: Teleport's metric names are standard ASCII
	// snake_case, not OpenMetrics-style UTF-8 names — expfmt.TextParser
	// has no usable default (its zero value panics as of
	// prometheus/common v0.71.0), so this must be explicit.
	parser := expfmt.NewTextParser(model.LegacyValidation)
	parsed, err := parser.TextToMetricFamilies(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("parsing metrics from %s: %w", url, err)
	}

	snap := &Snapshot{
		Target:    target,
		URL:       url,
		FetchedAt: time.Now(),
		Families:  make(map[string]*MetricFamily, len(parsed)),
	}
	for name, mf := range parsed {
		fam := &MetricFamily{Name: name, Type: mf.GetType().String(), Help: mf.GetHelp()}
		for _, m := range mf.GetMetric() {
			labels := make(map[string]string, len(m.GetLabel()))
			for _, l := range m.GetLabel() {
				labels[l.GetName()] = l.GetValue()
			}
			sample := Sample{Labels: labels}
			switch {
			case m.Counter != nil:
				sample.Value = m.GetCounter().GetValue()
			case m.Gauge != nil:
				sample.Value = m.GetGauge().GetValue()
			case m.Untyped != nil:
				sample.Value = m.GetUntyped().GetValue()
			case m.Histogram != nil:
				sample.Sum = m.GetHistogram().GetSampleSum()
				sample.Count = m.GetHistogram().GetSampleCount()
			case m.Summary != nil:
				sample.Sum = m.GetSummary().GetSampleSum()
				sample.Count = m.GetSummary().GetSampleCount()
			}
			fam.Samples = append(fam.Samples, sample)
		}
		snap.Families[name] = fam
	}
	return snap, nil
}

// SumValue adds up Value across every label combination of a
// counter/gauge family — the common case of "one number for this
// metric across all label variants" (e.g. total CPU seconds across all
// modes, total requests across all codes).
func (f *MetricFamily) SumValue() float64 {
	var total float64
	for _, s := range f.Samples {
		total += s.Value
	}
	return total
}

// SumHistogram adds up Sum and Count across every label combination —
// used to compute an aggregate average (Sum/Count) across all label
// variants of a histogram/summary family.
func (f *MetricFamily) SumHistogram() (sum float64, count uint64) {
	for _, s := range f.Samples {
		sum += s.Sum
		count += s.Count
	}
	return sum, count
}
