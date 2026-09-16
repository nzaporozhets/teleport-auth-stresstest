package attrib

// Metric names below are verified against the pinned Teleport v17.7.29
// source (not training-data memory) — see docs/methodology.md's M6
// notes for file:line citations. Namespace prefixing is inconsistent
// within Teleport's own source (some metrics get a "teleport_" prefix,
// sibling metrics in the same file don't) — these are the exact,
// checked full names, not a naming convention applied blindly.
const (
	// Standard Go/process collectors — always present (Teleport's
	// diagnostic handler includes prometheus.DefaultGatherer).
	MetricProcessCPUSeconds = "process_cpu_seconds_total"
	MetricGoGoroutines      = "go_goroutines"
	MetricGoHeapAllocBytes  = "go_memstats_heap_alloc_bytes"

	// Backend read/write latency — no "teleport_" prefix, unlike most
	// sibling metrics in the same source file.
	MetricBackendReadSeconds      = "backend_read_seconds"
	MetricBackendWriteSeconds     = "backend_write_seconds"
	MetricBackendBatchReadSeconds = "backend_batch_read_seconds"

	// Backend write throttling/contention.
	MetricBackendWriteRequestsFailed        = "backend_write_requests_failed_total"
	MetricBackendAtomicWriteConditionFailed = "teleport_backend_atomic_write_condition_failed"

	// gRPC server metrics (go-grpc-middleware Prometheus interceptor).
	// The latency histogram is conditional on cluster config
	// (Metrics.GRPCServerLatency) — check presence, don't assume it.
	MetricGRPCServerHandledTotal    = "grpc_server_handled_total"
	MetricGRPCServerStartedTotal    = "grpc_server_started_total"
	MetricGRPCServerHandlingSeconds = "grpc_server_handling_seconds"

	// Audit backend. The file-backend-specific ones
	// (audit_server_open_files etc.) are deliberately omitted — they're
	// meaningless for S3/DynamoDB/Firestore audit sinks.
	MetricAuditFailedEmitEvents = "audit_failed_emit_events"

	// Cache/watcher lag. cache_stale_events' own Help text: "a high
	// percentage of stale events can indicate a degraded backend" — a
	// direct, named signal for exactly the "slowed backend" bottleneck.
	MetricCacheEvents      = "teleport_cache_events"
	MetricCacheStaleEvents = "teleport_cache_stale_events"
	MetricCacheHealth      = "teleport_cache_health"
)

// No direct metric exists for these, per the same research pass —
// don't invent one. Evidence for these has to come from the
// generator's own outcome classification instead:
//   - Password-hashing cost: no histogram in lib/auth for the bcrypt
//     check specifically.
//   - Rate limiter engagement: lib/limiter has zero Prometheus
//     instrumentation; RateLimiterDetector below is deliberately
//     generator-side only, not because we couldn't find the metric
//     name but because Teleport doesn't expose one at all.
//   - Proxy-to-auth saturation: reverse-tunnel connection metrics
//     exist but measure SSH tunnel state (out of scope, see
//     instructions.md Non-goals), not an auth-client pool/queue depth.
