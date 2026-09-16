# Interpreting results

This document explains what each failure class in a report usually means
and which cluster knob it points at. It covers the taxonomy, ramp
outcomes, report shape, and ranked attribution — all scenario-agnostic
and unchanged by which of the six implemented scenarios (M2/M3/M7)
produced a given report.

## Outcome classes (`internal/scenario.Outcome`)

- **Success** — the operation completed as expected.
All five non-`Success` classes below are classified identically
regardless of which transport a scenario uses (gRPC for `cert-renewal`,
HTTP for `local-login-webauthn`) — see `internal/scenario.ClassifyError`
and `docs/methodology.md`'s note on `trace.WriteError`/`ReadError`.

- **Lockout** — the target user was locked out after too many consecutive
  failed auth attempts. This is *not* a latency or capacity signal: once a
  ramp starts producing real errors, lockouts cascade and can make an
  unrelated problem look like a wave of auth failures. A step's reported
  `errorRatePct` includes lockouts (informational, raw rate); the
  separate `abortErrorRatePct` field excludes them, and it's
  `abortErrorRatePct` — not `errorRatePct` — that decides whether a step
  passes (M4, `internal/ramp.evaluateStep`). If `errorRatePct` and
  `abortErrorRatePct` diverge a lot in a report, most of your "errors"
  are lockouts, not a real problem — nothing currently retires a
  locked-out user from the pool, though, so it'll keep getting retried
  and keep failing until the run ends. Points at: too-aggressive abort
  thresholds causing repeated failed logins on the same seeded users, or
  a scenario bug re-using stale credentials. It does *not* point at
  cluster capacity.
- **RateLimited** — the target's built-in per-IP connection/request
  limiter engaged. Points at: `proxy_limiter`/connection-limit settings
  being too low for the offered rate from your generator pod IPs — raise
  them as part of test setup (see docs/runbook.md) before concluding the
  auth service itself is the bottleneck.
- **Timeout** — the client gave up waiting for a response. Points at:
  queueing/saturation somewhere in the path (proxy, auth, or backend) —
  correlate with server-side CPU/backend-latency metrics (M6) before
  attributing.
- **ServerError** — the server returned a 5xx/internal error, *or the
  connection failed outright* (e.g. auth/proxy scaled to zero, connection
  refused). Points at: a real server-side fault or the target being
  unreachable — check auth/proxy logs, pod status, and backend health
  first. Never confuse this with `Timeout`: a hard connection failure is
  not "slow," it's "down."
- **ClientError** — a 4xx that isn't a lockout or rate limit (e.g. bad
  request, invalid credentials that aren't lockout-triggering). Points
  at: a generator/config bug (wrong password, expired token, malformed
  request) rather than the cluster — investigate the generator before the
  cluster.

## Phase timings (M3)

`local-login-webauthn`'s report phases are `mfa-begin` (network: the
password submission that returns a WebAuthn challenge), `mfa-solve`
(local: signing the challenge with the soft authenticator — should be
microseconds, not milliseconds; if it isn't, something is generating
keys instead of reusing the registered device) and `mfa-finish`
(network: submitting the signed assertion, which returns certs
directly). The three should sum to very close to the scenario's total
`Execute` wall-clock time — if they don't, something in the scenario is
doing unmeasured work, which is exactly what M3's "phase timings sum to
within 5%" acceptance criterion exists to catch.

## Generator health and run outcomes (M4)

A breaking point is only meaningful if the load generator wasn't the
thing that broke first (domain constraint #7). Every step's report entry
carries `generatorHealth` (worst-observed CPU%/goroutines/FDs/ephemeral
connections during that step) and `generatorLimited` (whether any of
those crossed `load.generatorLimits`). If *any* step in a run is
generator-limited, the whole run's `outcome` is `"generator-limited"` and
`breakingPointRPS` is omitted, even if earlier steps looked like clean
passes — treat that result as "inconclusive, re-run with more generator
capacity or more pods," not as a finding about the cluster. A run's
`outcome` is one of:

- `"converged"` — at least one step passed, the generator was never
  saturated, and the run stopped on `consecutiveBadSteps` or `maxRPS`.
  `breakingPointRPS` is the highest offered rate whose step passed.
- `"generator-limited"` — see above. No breaking point is reported.
- `"inconclusive"` — no step ever passed, including the very first one
  at `load.ramp.startRPS`. Either `startRPS` already exceeds the
  cluster's limit, or the abort thresholds are stricter than the cluster
  can ever satisfy — check `load.abort` before assuming the cluster is
  actually this fragile.

`outcomeReason` is populated for the latter two and explains which.

## Multi-pod (aggregate) reports (M5)

An `authload aggregate` report has the exact same shape as a single-pod
one — same `meta`/`steps`/`outcome` fields, same Markdown layout. The
differences are in how each step's numbers came to be: `offeredRPS` is
the *sum* of every pod's own offered rate for that step (the fleet-wide
target, not one pod's share of it), and every percentile comes from a
single HDR histogram that every pod's own histogram was losslessly
merged into — not an average of each pod's individual percentiles,
which would not be the fleet's true percentile. `generatorHealth` is the
worst reading across all pods for that step, so one saturated pod is
enough to mark the whole step (and thus the whole run)
`generatorLimited`, even if every other pod looked healthy.

## Ranked limiting resources (M6)

A failing, non-generator-limited step's report entry carries
`rankedCauses`: candidate cluster-side explanations, sorted by score
descending, each with a `name`, a `score`, and `evidence` bullets citing
the actual metric values that produced it. This is attribution, not
proof — it correlates before/after server metric snapshots (from
`observability.scrape`) and the step's own generator-side outcome mix
against a small set of known failure signatures, per instructions.md's
"Attribution" requirement. Absent entirely (`rankedCauses` omitted) means
either the step passed, it was generator-limited (deliberately not
ranked — see below), or no scrape targets were reachable/configured.

Current detectors and what each one actually means if it's top-ranked:

- **`<target>-cpu-saturation`** — `process_cpu_seconds_total` delta over
  the step's wall time, divided by `observability.scrape[].cores`,
  crossed a high-utilization threshold. Points at: that process (auth or
  proxy) is CPU-bound — the login/cert-issuance work itself (WebAuthn
  signature verification, password hashing, cert signing), not something
  downstream.
- **`<target>-backend-latency`** — `backend_read_seconds`/
  `backend_write_seconds` (note: no `teleport_` prefix, unlike most other
  metrics) average latency grew relative to baseline (or, with no
  baseline available, crossed an absolute-ms threshold). Points at: the
  backend store (etcd/DynamoDB/Firestore/etc.), not the Teleport process
  itself — check its own capacity/throttling, not auth/proxy CPU.
- **`<target>-goroutine-growth`** — `go_goroutines` grew well beyond
  baseline. Points at: work piling up faster than it's being drained
  (a queue backing up somewhere in that process) — often a precursor to,
  or co-occurring with, CPU saturation or backend latency, worth
  correlating with both before concluding it's an independent cause.
- **`<target>-cache-staleness`** — `teleport_cache_stale_events` grew
  relative to `teleport_cache_events`. Per that metric's own Help text,
  "a high percentage of stale events can indicate a degraded backend" —
  effectively a second, independent signal pointing at the same backend
  as `backend-latency`, useful when read/write latency metrics aren't
  present on a given version but this one is.
- **`rate-limiter-engaged`** — the step's own generator-side outcome mix
  was dominated by `RateLimited`. Needs no server metric at all: verified
  against source, Teleport's per-IP login-endpoint limiter
  (`lib/limiter`) has zero Prometheus instrumentation, so this is the
  only detector that works with no `observability.scrape` configured or
  reachable at all. Points at: your generator's source-IP diversity, not
  cluster capacity — see docs/runbook.md's rate-limiter note; this is
  *not* a cluster bottleneck finding, and a high score here suggests the
  run's breaking point is an artifact of your own pod topology.

**Known gaps, not oversights**: there is no detector for password-hashing
cost, admin-action-MFA overhead, or proxy-to-auth-connection saturation —
verified against source that no Prometheus metric exists for any of
these on the pinned version, so no detector could be built without
inventing a proxy metric that doesn't reflect anything real. If one of
these is actually your bottleneck, it won't show up in `rankedCauses` at
all; don't read an empty/low-scoring list as proof the cluster wasn't the
problem.

## Coordinated omission

Reports state which arrival model (`load.model`: `open` or `closed`) was
used. Only trust `open`-model p99/p99.9 numbers as a measure of what a
real client population would experience under load; a `closed`-model run
systematically hides queueing delay because a stalled worker stops
generating new requests instead of falling behind, which throttles the
offered rate to the achieved rate.
