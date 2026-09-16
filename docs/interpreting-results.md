# Interpreting results

This document explains what each failure class in a report usually means
and which cluster knob it points at. It will grow as scenarios (M2+),
the ramp/attribution logic (M4/M6), and the report format (M4) land —
for now it covers the taxonomy already implemented.

## Outcome classes (`internal/scenario.Outcome`)

- **Success** — the operation completed as expected.
All five non-`Success` classes below are classified identically
regardless of which transport a scenario uses (gRPC for `cert-renewal`,
HTTP for `local-login-webauthn`) — see `internal/scenario.ClassifyError`
and `docs/methodology.md`'s note on `trace.WriteError`/`ReadError`.

- **Lockout** — the target user was locked out after too many consecutive
  failed auth attempts. This is *not* a latency or capacity signal: once a
  ramp starts producing real errors, lockouts cascade and can make an
  unrelated problem look like a wave of auth failures. **Current state
  (M3): lockouts are classified into this distinct outcome, but
  `collect.Snapshot.ErrorRatePct` still counts them in the error rate,
  and nothing retires a locked-out user from the pool yet** — both are
  ramp-controller responsibilities, pending M4. Until then, if you see
  nonzero `lockout` counts in a report, subtract them from the error rate
  by hand before judging abort thresholds. Points at: too-aggressive
  abort thresholds causing repeated failed logins on the same seeded
  users, or a scenario bug re-using stale credentials. It does *not*
  point at cluster capacity.
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

## Generator health

A breaking point is only meaningful if the load generator wasn't the
thing that broke first (domain constraint #7). Once the ramp package
(M4) lands, a run that crosses a generator CPU/goroutine/FD/ephemeral-port
threshold will be marked `generator-limited` in the report instead of
reporting a cluster breaking point — treat that result as "inconclusive,
re-run with more generator capacity or more pods," not as a finding about
the cluster.

## Report shape (M2)

`authload run`'s JSON report has `meta` (harness/git/cluster/scenario
identity), `steps` (currently always exactly one — the ramp's multi-step
table is M4), and `reproCommand`. Each step's `outcomes` map is keyed by
the `Outcome.String()` values above (`"success"`, `"lockout"`,
`"rate-limited"`, `"timeout"`, `"server-error"`, `"client-error"`).
Percentiles (`p50Ms`/`p90Ms`/`p99Ms`/`p999Ms`) come from a full-fidelity
HDR histogram, not fixed buckets, and are computed over *every* completed
call regardless of outcome — a slow failure still shows up in the tail.

## Coordinated omission

Reports state which arrival model (`load.model`: `open` or `closed`) was
used. Only trust `open`-model p99/p99.9 numbers as a measure of what a
real client population would experience under load; a `closed`-model run
systematically hides queueing delay because a stalled worker stops
generating new requests instead of falling behind, which throttles the
offered rate to the achieved rate.
