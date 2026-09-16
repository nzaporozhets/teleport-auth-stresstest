# Runbook

## Build environment

The pinned Teleport `v17.7.29` commit's `api` Go module requires
`go 1.25.14` (see its `api/go.mod`, independent of the root module's own
`go 1.23.3` directive — don't assume the two agree). Building against it
with a Go toolchain new enough to satisfy that also pulls in a newer
Unicode dataset than some transitive dependencies expect:
`github.com/charlievieth/strcase` panics at init with a
`UnicodeVersion != unicode.Version` mismatch unless it's at v0.0.6 or
later (fixed in this repo's `go.mod` — if you see that panic after
touching dependencies, that's the cause).

## Before seeding or running load against a real cluster

1. **Confirm the target is disposable.** `authseed`/`authload` refuse to
   run unless `target.guardrail.requireClusterName` matches the actually
   connected cluster's name and `target.guardrail.confirmPhrase` is
   exactly `"I am not in production"`. This is enforced, not just
   documented — see `internal/config/validate.go` and
   `internal/identity/admin.go`.
2. **The proxy's per-IP login-endpoint rate limiter is not raisable via
   config — plan for source-IP diversity instead.** Verified against the
   pinned v17.7.29 source (confirmed live against a real v18.10.4
   cluster, see below): the limiter guarding `/webapi/mfa/login/begin`
   and `/webapi/mfa/login/finish` (`lib/web/apiserver.go`'s `h.limiter`,
   comment: *"used to limit unauthenticated challenge generation for
   passwordless and for unauthenticated metrics"*) is built from
   **hardcoded constants** — `lib/defaults/defaults.go`:
   `LimiterAverage = 20` requests/minute, `LimiterBurst = 40`, per source
   IP — not from `teleport.yaml`/Helm values. Teleport's documented
   `connection_limits` config field is real but feeds a *different,*
   lower-level connection limiter, not this one. **This means a
   single-source-IP generator will hit this limiter at roughly
   0.33 sustained req/sec no matter what you set in the cluster config**
   — the only real fix is exactly what M5's multi-pod design already
   assumes: distribute load across genuinely different source IPs
   (separate pods on separate nodes/egress paths), not raise a setting.
   Earlier drafts of this runbook speculated this was configurable
   without having verified it — it isn't, at least for this specific
   endpoint limiter; corrected here after hitting it on a real cluster.
   *(Other limiters — e.g. on authenticated gRPC endpoints — may behave
   differently; not yet checked. If you find one that reads from cluster
   config, update this note.)*
3. **Check audit backend headroom.** Every login and cert issuance writes
   audit events; a long high-rate ramp can produce a large volume. Check
   your audit backend's (S3/Firestore/DynamoDB/etc.) write capacity and
   retention settings before a long run. `authseed apply`'s pre-flight
   summary prints a rough estimate (`~3 events/user` for seeding); the
   ramp's own estimate is pending M4/M6.
4. **Never point `identity.adminIdentityFile` at anything you're not
   willing to have used for user/role/token management only.** It is read
   by `authseed` and by `internal/identity.NewAdminClient`; nothing in
   the load path (`internal/scenario` implementations' `Execute`) may
   import or receive it.
5. **Use a Machine ID bot identity for `identity.adminIdentityFile`, not
   a plain local-admin identity file, if the cluster enforces
   `second_factor: webauthn` without TOTP.** `cert-renewal`'s bootstrap
   step (M2) impersonates seeded users via `GenerateUserCerts`, which
   triggers a per-call Admin Action MFA challenge for a plain local admin
   under that cluster setting — impractical once `userCount` is in the
   thousands. Bot identities (and callers impersonated by an admin-role
   host) are exempt. See docs/methodology.md's M2 implementation notes.
6. **Grant the admin identity's role `allow.impersonate` over
   `fixtures.roles`/the seeded users**, or use the builtin `Admin` role.
   Without it, `cert-renewal`'s bootstrap step fails with `AccessDenied`
   — there's no way to check this from the config file, so expect to
   discover it the first time `authload run` gets to scenario `Setup`.
7. **Set `target.insecureSkipVerify: true` only for disposable clusters
   with a self-signed proxy certificate.** `local-login-webauthn` (M3)
   talks to the proxy's web API over plain HTTPS with the Go standard
   library's TLS verification; it defaults to verifying (secure by
   default). This is unrelated to how the gRPC admin/scenario clients
   trust the cluster — setting this doesn't affect them.

## Seeding fixtures (M1)

```
authseed validate -c scenarios/example.yaml
authseed apply -c scenarios/example.yaml       # prints pre-flight summary, does nothing else
authseed apply -c scenarios/example.yaml -y    # actually creates roles/users/devices/keypool
authseed teardown -c scenarios/example.yaml -y # deletes only users matching fixtures.userPrefix
```

`apply` is safe to re-run: user/role resources converge (`UpsertUser`/
`UpsertRole`), though each re-run currently rotates every user's password
and MFA device (see docs/methodology.md's idempotency note) rather than
being a true no-op — for a large `userCount` this means re-applying is
not free, just safe.

`fixtures.statePath` (JSON) contains every seeded user's plaintext
password and WebAuthn/TOTP private material, plus the raw private keys of
the pre-generated keypair pool. Treat it like the admin identity file:
it's written with `0600` permissions, but it is not encrypted at rest.

## Running load (M2-M4: cert-renewal, local-login-webauthn, full ramp)

```
authload validate -c scenarios/example.yaml
authload run -c scenarios/example.yaml       # prints pre-flight summary, generates no load
authload run -c scenarios/example.yaml -y    # runs the full ramp, writes JSON/Markdown reports
```

`load.scenario` must be `cert-renewal` (M2) or `local-login-webauthn`
(M3); any other value fails fast in the pre-flight step, before touching
fixtures or the cluster. `local-login-webauthn` needs
`fixtures.secondFactor: webauthn`-seeded users in the fixture state (it
skips any seeded user with a different second factor, and fails Setup if
none match).

`authload run -y` (M4) runs the full step plan: warm up at
`load.ramp.startRPS`, then each step at an increasing offered rate for
`load.ramp.stepDuration`, discarding `load.ramp.settle` after every
subsequent rate change, until `load.abort.consecutiveBadSteps` failures
in a row or `load.ramp.maxRPS` is reached. `load.model: closed` is
implemented in `internal/driver` but this command still refuses it, so a
report can never accidentally end up unlabeled as to which model
produced it. `load.generatorLimits` (all four sub-fields) is required —
there's no cluster-independent default CPU/goroutine/FD/ephemeral-port
ceiling that's safe to silently apply, so a config that omits it fails
validation rather than quietly running without saturation detection.

Reports land in `report.outputDir` as `report-<UTC timestamp>.{json,md}`,
one file per format listed in `report.formats`. The JSON `outcome` field
is `"converged"` (with a `breakingPointRPS`), `"generator-limited"`, or
`"inconclusive"` — see docs/interpreting-results.md for what each means
and docs/methodology.md's M4 notes for exactly how generator-limited
overrides an otherwise-passing step.

## Multi-pod runs (M5)

A single pod cannot generate enough TLS handshakes/logins to break a real
auth service, and will hit per-IP rate limits first (instructions.md
"Distributed execution"). `authload run` supports sharding directly:

```
authload run -c config.yaml -y \
  --shard-index 3 --shard-count 8 \
  --start-at 2026-01-01T00:00:00Z \
  --results-dir /data/results/raw
```

- `--shard-count` divides `load.ramp.startRPS`/`stepRPS`/`maxRPS` by N;
  `--shard-index` (0-based) picks this pod's disjoint slice of the seeded
  user pool and keypair pool (`identity.FixtureState.Shard` — the same
  user's index in `Users` and the same index in the keypair pool always
  land in the same shard, preserving scenarios' 1:1 pairing, e.g.
  `cert-renewal`). `--shard-index` defaults to `$JOB_COMPLETION_INDEX` if
  unset, so a Kubernetes Indexed Job needs no per-pod templating at all.
- `--start-at` is the shared wall-clock rendezvous: every pod waits until
  this exact timestamp before its *step plan* begins (each pod's own
  Setup/bootstrap still runs independently and as soon as it's ready).
  There is no leader election and no runtime RPC between pods — every
  pod is simply given the same value.
- `--results-dir`, if set, makes the pod write its raw per-step HDR
  histograms and counters there instead of writing its own final report.
  When sharded, a pod also does **not** stop early on
  `load.abort.consecutiveBadSteps` — it runs the full range up to
  `load.ramp.maxRPS` unconditionally, because only the fleet-wide
  aggregate's verdict matters; letting one noisy shard stop early would
  leave other pods' later steps with nothing to merge against.

Once every pod in the fleet has finished:

```
authload aggregate -c config.yaml --results-dir /data/results/raw
```

This reads every pod's raw step files, merges each step's HDR histograms
losslessly (`internal/collect.MergeRaw` — merged percentiles are exact,
not an average of each pod's own percentiles) and outcome counts, sums
each step's offered rate back to the fleet-wide target, and
re-evaluates `load.abort`/`load.generatorLimits` against the *merged*
statistics — a fleet-wide aggregate can cross a threshold no individual
shard did on its own, or vice versa, so this is not a simple AND/OR of
each shard's verdict. It needs no cluster connection at all: this is
why "a run can be re-analyzed without re-running load" — you can re-run
just `authload aggregate` against the same `--results-dir` as many times
as you want (e.g. after changing `load.abort` in the config to see how
sensitive the breaking point is to it).

### Kubernetes (Helm chart)

`deploy/helm/teleport-auth-stress` has three Job templates — a
single-pod seed Job, an `Indexed` load Job (`completions`/`parallelism`
= `values.podCount`, giving every pod `$JOB_COMPLETION_INDEX`
automatically), and a single-pod aggregate Job — all sharing one
`ReadWriteMany` PVC (needs an RWX-capable storage class: NFS, EFS, Azure
Files, Filestore, etc.) for `fixtures.statePath` and the raw results
directory. `values.config` is the full teleport-auth-stress YAML,
rendered verbatim into a ConfigMap and mounted identically into every
pod — set `identity.adminIdentityFile`/`fixtures.statePath` in it to
`/secrets/identity.pem`/`/data/fixtures.json` (or wherever you mount
them) to match the chart's volume mounts. `values.adminIdentity` is the
identity file's contents, mounted from a Secret. The chart does not
auto-sequence the three Jobs (Helm hook ordering for long-running Jobs is
fragile) — run them one at a time and wait for each to complete:

```
helm template loadtest deploy/helm/teleport-auth-stress -f my-values.yaml \
  --show-only templates/job-seed.yaml | kubectl apply -f -
# wait for it to complete
helm template loadtest deploy/helm/teleport-auth-stress -f my-values.yaml \
  --show-only templates/job-load.yaml | kubectl apply -f -
# wait for all podCount completions
helm template loadtest deploy/helm/teleport-auth-stress -f my-values.yaml \
  --show-only templates/job-aggregate.yaml | kubectl apply -f -
```

Re-run `helm template`/`kubectl apply` for the load Job as many times as
you want against the same seeded fixtures (each run gets a fresh
`--start-at`, computed at render time) before re-running the seed Job.

*Not verified against a real Kubernetes cluster in this sandbox* — `helm
lint`/`helm template` both pass and the rendered YAML round-trips through
a YAML parser cleanly (checked in this environment, which does have Helm
but no cluster), but no `kubectl apply` or actual Job scheduling has been
tested.

## Attribution: server-side scraping, pprof, Grafana dashboards (M6)

Add `observability.scrape` entries pointing at each Teleport process's
metrics endpoint to get ranked candidate causes for failing steps in the
report, plus a generated Grafana dashboard per target:

```yaml
observability:
  scrape:
    - name: auth
      url: https://auth.internal:3000/metrics
      cores: 2          # optional: matches this process's CPU limit/request;
                         # defaults to 1 if omitted (only skews the
                         # CPU-saturation score, not a safety check)
    - name: proxy
      url: https://proxy.internal:3000/metrics
      cores: 2
  pprof:
    enabled: true
    targets: [auth]      # must name a target above
    captureAtEachStep: true
```

- **`observability.scrape[].url` must be reachable from wherever
  `authload run` runs** — usually not the public proxy address.
  Teleport's `/metrics` and `/debug/pprof/*` are served on `diag_addr`,
  which **defaults to loopback (`127.0.0.1:3000`) and is not exposed
  externally** unless you've explicitly configured
  `diag_addr`/`prometheus_addr`/an equivalent Helm value to bind
  elsewhere or expose it via a Service. Confirmed against a live
  cluster in this session: `/metrics` was unreachable from outside the
  auth pod with the default config. If every scrape target is
  unreachable, `authload run` still runs and still reports
  `rate-limiter-engaged` findings (the one detector needing no server
  metric) — it just skips server-side detectors/dashboards for that run
  and logs a warning per target, rather than failing.
- **Attribution never blocks or fails a run.** A scrape failure, a
  missing metric, or a dashboard-write error all log at `WARN` and are
  skipped — this is a diagnostic aid layered on top of the load test,
  not part of its pass/fail logic.
- **What you get in `report.outputDir`**: `grafana-<target>-dashboard.json`
  per reachable scrape target (import directly into Grafana — only
  panels whose underlying metric actually exists on this cluster/version
  are included, with a startup warning naming any panel that was
  skipped), and, if `pprof.enabled`, `pprof-<target>-step<N>.pb.gz` per
  step per pprof target (`go tool pprof pprof-auth-step3.pb.gz`).
  See `deploy/grafana/example-*-dashboard.json` for what the full
  (all-metrics-present) 6-panel layout looks like.
- **Ranked causes live in the report itself**, under each failing step —
  see docs/interpreting-results.md's "Ranked limiting resources" section
  for what a candidate's score/evidence mean and which failure modes are
  and aren't currently detectable this way.
- **Not yet wired into `authload aggregate`**: attribution runs per-pod
  during `authload run`, but a multi-pod aggregate report has no ranked
  causes (see docs/methodology.md's M6 notes for why).

## kind-based integration testing

This repo has no bundled Teleport-on-Kubernetes manifests — provision a
disposable cluster and install Teleport yourself, then point a config at
it:

```
make kind-up                     # creates a local kind cluster named auth-stress
helm repo add teleport https://charts.releases.teleport.dev
helm repo update
helm install teleport-cluster teleport/teleport-cluster \
  --create-namespace -n teleport-cluster \
  --set clusterName=<your-kind-cluster-hostname>
# ... wait for rollout, then generate an admin identity file with tctl,
# write a config pointing fixtures.statePath/target.proxyAddr/
# target.guardrail.requireClusterName at it, and run authseed/authload
# against it.
make kind-down
```

### Live spot-check (2026-09-16, teleport2.cavj.dev, Teleport v18.10.4)

Not a substitute for the full M1-M5 acceptance criteria below (small
scale, single pod, single run, and a different major version than this
toolkit is pinned to — v18.10.4 vs. the v17.7.29 the client code is
written against), but real signal from a real cluster:

- `authseed apply -y`: seeded 5 real local WebAuthn users. The soft
  WebAuthn registration ceremony (`internal/identity/webauthn_soft.go`)
  was accepted by a live v18.10.4 auth server, not just our own
  `go-webauthn`-based tests.
- `authload run local-login-webauthn -y`: real password+WebAuthn HTTP
  logins against the live proxy, certs issued back. A clean run (rate
  kept under the login endpoint's per-IP limiter, see below) got 23/23
  success, p50/p99 ≈ 257/310ms.
- Rate-limiter classification: a faster run (4 RPS from one source IP)
  correctly classified the resulting flood of 429s as `rate-limited`,
  distinct from other error classes — see the corrected limiter note
  below, discovered by hitting it for real.
- `cert-renewal`: failed cleanly with `access denied: impersonation is
  not allowed` when the admin identity's role lacked an `impersonate`
  grant — expected, and the error surfaced clearly rather than hanging
  or being miscategorized.
- The v17.7.29-pinned client interoperated with the live v18.10.4 server
  without issue for every call made above (`Ping`, `GetUsers`,
  `UpsertUser`/`UpsertRole`/`CreateResetPasswordToken`/
  `CreateRegisterChallenge`/`ChangeUserAuthentication`, the web login
  endpoints, `GenerateUserCerts`). Not exhaustive — only what got
  exercised — but zero version-skew issues hit so far.

*Not verified end-to-end at the scale/rigor the milestones actually
require* — the sandbox this was built in has no Docker/kind/kubectl
available (it does have Helm, used above for `helm lint`/`helm template`
only), so none of M1's through M5's full acceptance criteria have been
run. Each is checked at the unit level only, plus the live spot-check
above for the pieces it touched:
- M1 ("seeds 1,000 WebAuthn users against a kind-based Teleport cluster
  in under two minutes"): `internal/identity/*_test.go` verifies the soft
  WebAuthn/TOTP authenticators against the real
  `go-webauthn`/`pquerna-otp` libraries.
- M2 ("a fixed-rate 2-minute run at 20 RPS reports achieved throughput
  within 2% of offered, and auth scaled to zero mid-run is classified
  correctly"): `internal/driver/*_test.go` verifies the open-loop
  scheduler's timing mechanics (not the 2% precision claim, which needs a
  real cluster); `internal/scenario/classify_test.go` verifies that an
  `Unavailable` gRPC status maps to `ServerError`, not latency, using the
  exact `trail.FromGRPC`/`RemoteError` error-translation path the real
  client uses.
- M3 ("phase timings sum to total round-trip within 5%; lockouts and
  rate-limit responses appear as their own classes; no keypair
  generation occurs inside Execute"): `internal/scenario/locallogin_test.go`
  checks all three directly — including a fake proxy server that
  cryptographically verifies every WebAuthn assertion `Execute` produces
  using the real `go-webauthn` library, and a lockout/rate-limit/
  connection-refused test built on the real `trace.WriteError`/`ReadError`
  pair Teleport itself uses.
- M4 ("against an intentionally undersized cluster, a ramp converges on
  a knee and reports the same value within 15% across three consecutive
  runs"): `internal/ramp/ramp_test.go` verifies the step-plan control
  flow (knee detection, generator-limited override, inconclusive
  detection, warmup/settle discard timing) against synthetic tasks with
  scripted degradation — deterministic by construction (degradation is
  triggered via the `onStep` callback at an exact step boundary, not a
  wall-clock guess, precisely to avoid the timing flakiness a naive
  version of this test had during development). It does not and cannot
  verify the 15%-reproducibility claim itself, which is a statement about
  a real cluster's behavior under repeated load, not about this code.
- M5 ("an 8-pod run produces one merged report whose aggregate
  percentiles match a single-pod run at equivalent total rate within
  10%"): `internal/collect/collect_test.go`'s
  `TestExportMergeRaw_LosslessAgainstGroundTruth` proves the merge is
  *exact* against a single collector fed the identical union of samples
  directly (a stronger claim than "within 10%") — the only reason a real
  multi-pod run wouldn't match a single-pod run at the same total rate
  *exactly* is genuine measurement variance between separate processes
  (scheduling, network path differences), not anything about the merge
  math. `internal/aggregate/aggregate_test.go` verifies the fleet-wide
  sum-of-offered-rates and re-evaluation-against-merged-stats behavior.
  The Helm chart is verified with `helm lint`/`helm template` plus a
  YAML-parse round-trip in this sandbox; no `kubectl apply` or real Job
  scheduling has been tested.

Re-run all five milestones' acceptance criteria against a real kind
cluster before relying on any of these claims.
