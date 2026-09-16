package attrib

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

const sampleExposition = `# HELP process_cpu_seconds_total Total user and system CPU time spent in seconds.
# TYPE process_cpu_seconds_total counter
process_cpu_seconds_total 12.34
# HELP go_goroutines Number of goroutines that currently exist.
# TYPE go_goroutines gauge
go_goroutines 42
# HELP grpc_server_handled_total Total number of RPCs completed on the server, regardless of success or failure.
# TYPE grpc_server_handled_total counter
grpc_server_handled_total{grpc_code="OK",grpc_method="Ping"} 100
grpc_server_handled_total{grpc_code="ResourceExhausted",grpc_method="Ping"} 5
# HELP teleport_backend_requests_seconds Latency of backend operations.
# TYPE teleport_backend_requests_seconds histogram
teleport_backend_requests_seconds_bucket{le="0.01"} 10
teleport_backend_requests_seconds_bucket{le="0.1"} 18
teleport_backend_requests_seconds_bucket{le="+Inf"} 20
teleport_backend_requests_seconds_sum 1.5
teleport_backend_requests_seconds_count 20
`

func TestFetch_ParsesRealExpositionFormat(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(sampleExposition)) //nolint:errcheck
	}))
	defer srv.Close()

	snap, err := Fetch(context.Background(), srv.Client(), "auth", srv.URL)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if !snap.Has("process_cpu_seconds_total") {
		t.Error("expected process_cpu_seconds_total to be present")
	}
	if !snap.Has("go_goroutines") {
		t.Error("expected go_goroutines to be present")
	}
	if snap.Has("nonexistent_metric") {
		t.Error("Has() returned true for a metric that isn't there")
	}

	cpu := snap.Families["process_cpu_seconds_total"]
	if cpu.Type != "COUNTER" && cpu.Type != "counter" {
		t.Errorf("process_cpu_seconds_total type = %q, want counter", cpu.Type)
	}
	if got := cpu.SumValue(); got != 12.34 {
		t.Errorf("process_cpu_seconds_total SumValue() = %v, want 12.34", got)
	}

	goroutines := snap.Families["go_goroutines"]
	if got := goroutines.SumValue(); got != 42 {
		t.Errorf("go_goroutines SumValue() = %v, want 42", got)
	}

	grpc := snap.Families["grpc_server_handled_total"]
	if len(grpc.Samples) != 2 {
		t.Fatalf("grpc_server_handled_total has %d samples, want 2 (one per label combination)", len(grpc.Samples))
	}
	var resourceExhausted float64
	for _, s := range grpc.Samples {
		if s.Labels["grpc_code"] == "ResourceExhausted" {
			resourceExhausted = s.Value
		}
	}
	if resourceExhausted != 5 {
		t.Errorf("ResourceExhausted count = %v, want 5", resourceExhausted)
	}

	backend := snap.Families["teleport_backend_requests_seconds"]
	sum, count := backend.SumHistogram()
	if sum != 1.5 || count != 20 {
		t.Errorf("teleport_backend_requests_seconds SumHistogram() = (%v, %v), want (1.5, 20)", sum, count)
	}
}

func TestFetch_NonOKStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	if _, err := Fetch(context.Background(), srv.Client(), "auth", srv.URL); err == nil {
		t.Error("expected error for non-200 response")
	}
}

func TestFetch_MalformedBody(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("this is not valid prometheus exposition format {{{")) //nolint:errcheck
	}))
	defer srv.Close()

	if _, err := Fetch(context.Background(), srv.Client(), "auth", srv.URL); err == nil {
		t.Error("expected a parse error for malformed body")
	}
}
