# Task: Build `teleport-auth-stress` — a breaking-point stress toolkit for Teleport auth
 
## Objective
 
Build a Go toolkit that drives authentication load against a **self-hosted Teleport cluster running on Kubernetes (Helm)** and determines the **maximum sustainable rate of logins and certificate issuance before the cluster degrades**, along with evidence of *what* broke first.
 
The deliverable is not a benchmark number. It is a repeatable harness that produces: a knee point, a named limiting resource, and the server-side evidence supporting that attribution.
 
---
 
## Assumptions (change these if wrong before starting)
 
| Assumption | Default | Notes |
|---|---|---|
| Teleport version | v17.x | Pin exactly. Metric names and API signatures differ across majors — verify against the target, don't trust training data. |
| Backend | Unknown; must be detected and recorded | DynamoDB, etcd, Postgres and Firestore fail in very different ways. The report must state which one was in play. |
| Auth connector under test | Local users (password + second factor) | SSO is out of scope (see Non-goals). |
| Harness runs | In the same k8s cluster, separate namespace | Must also support running from outside via the public proxy address. |
| Target is a disposable load-test cluster | Yes | Guardrails assume this and must refuse to run otherwise. |
 
If any assumption is wrong, stop and ask before writing code.
 
---
 
## Scope
 
**In scope**
- Local user login end-to-end through the proxy web API (password → second factor → user certificates).
- Certificate issuance and renewal over the auth gRPC API.
- Machine ID (`tbot`) join and renewal loops.
- Ramp-to-failure control, breaking-point detection, and attribution.
**Non-goals** — do not build these, do not stub them "for later":
- SSH session establishment, session recording, or session playback load.
- Agent/node fan-out and inventory heartbeat scale.
- Kubernetes, database, or application access proxying (certificate *issuance* for those routes is in scope; using the certificates is not).
- SAML/OIDC login (requires a mock IdP — separate project).
- Chaos or fault injection.
- Cost modelling.
---
 
## Critical domain constraints
 
These are the things that most commonly make a Teleport auth load test produce garbage numbers. Handle each one explicitly; each needs a corresponding note in `docs/methodology.md`.
 
1. **TOTP codes cannot be replayed.** Teleport rejects a reused code, and codes live in ~30s windows. A TOTP scenario is therefore capped at roughly one login per user per 30 seconds. Either seed tens of thousands of users or use a soft WebAuthn authenticator, which has no such limit. **Make WebAuthn the primary login scenario and TOTP a secondary one.**
2. **Account lockout.** Teleport locks a local user after a small number of consecutive failed attempts. Once a ramp starts producing errors, lockouts will cascade and turn a latency problem into a fake authentication failure. The harness must (a) classify lockout errors distinctly from other 4xx, (b) retire a locked user from the pool rather than retrying it, and (c) report lockout counts separately, never folded into the error rate that drives abort criteria.
3. **Built-in rate limiting.** Teleport applies per-IP connection and request limiting to the web API. Running thousands of requests per second from a handful of pod IPs will hit the limiter long before the auth service is saturated. The toolkit must detect limiter responses as a distinct error class and the docs must state which cluster settings to raise (and that raising them is part of the test setup, not cheating).
4. **Client-side key generation is not part of the server's work.** If each virtual user generates a keypair inline, a large share of measured latency is the generator's own CPU. Pre-generate a pool of keypairs during setup and draw from it in the hot path. Record the pool size and key algorithm in the report.
5. **Audit event volume.** Every login writes audit events. At high rates this saturates the audit backend and inflates storage. The harness must estimate and report total events emitted, and the runbook must tell operators to check audit backend headroom before a long ramp.
6. **Coordinated omission.** Use an **open-loop** driver: a Poisson (or fixed-interval) arrival process with a fixed target rate, where latency is measured from *intended* send time, not from when a worker became free. A closed-loop `N goroutines in a tight loop` design will hide exactly the queueing behaviour this test exists to find. A closed-loop mode may exist as an option, but it is not the default and the report must label which was used.
7. **Generator saturation.** A breaking point is only real if the generator wasn't the thing that broke. Continuously sample generator CPU, goroutine count, open file descriptors, and ephemeral port usage. If any crosses a threshold, mark the run `generator-limited` and refuse to report a cluster breaking point.
---
 
## Architecture
 
```
teleport-auth-stress/
├── cmd/
│   ├── authload/           # load generator (one process per pod)
│   └── authseed/           # fixture provisioning + teardown
├── internal/
│   ├── config/             # YAML schema, validation, guardrail checks
│   ├── identity/           # admin client, keypair pool, soft authenticators
│   ├── scenario/           # Scenario interface + implementations
│   ├── driver/             # open/closed loop arrival control
│   ├── ramp/               # step plan, abort criteria, knee detection
│   ├── collect/            # HDR histograms, error taxonomy, server scraping
│   ├── attrib/             # limiting-resource attribution
│   └── report/             # JSON + Markdown output
├── deploy/
│   ├── helm/               # harness chart (Job/StatefulSet, RBAC, secrets)
│   └── grafana/            # dashboard, generated from live /metrics
├── scenarios/              # example YAML configs
├── docs/
│   ├── methodology.md
│   ├── runbook.md
│   └── interpreting-results.md
└── Makefile
```
 
### Scenario interface
 
Every workload implements one interface so the driver, collector, and ramp controller stay workload-agnostic:
 
```go
type Scenario interface {
    Name() string
    // Setup runs once per process before load starts.
    Setup(ctx context.Context, env *Env) error
    // Execute performs exactly one logical operation and returns
    // per-phase timings. It must be safe for concurrent use and must
    // not allocate expensive crypto material.
    Execute(ctx context.Context) (Result, error)
    Teardown(ctx context.Context) error
}
 
type Result struct {
    Phases  []Phase      // e.g. dial, tls, password, mfa, cert-issue
    Outcome Outcome      // Success, Lockout, RateLimited, Timeout, ServerError, ClientError
    Bytes   int64
}
```
 
### Scenarios to implement
 
| Name | What it exercises | Priority |
|---|---|---|
| `cert-renewal` | gRPC user-certificate generation with an already-valid identity. No password hashing. Isolates CA signing, RBAC evaluation, and backend reads. | **First** — simplest path to a working end-to-end pipeline |
| `local-login-webauthn` | Full proxy web login with a soft authenticator. The headline scenario. | **Primary** |
| `local-login-totp` | Same, with TOTP. Subject to the 30s constraint above. | Secondary |
| `bot-join-renew` | Machine ID join (token method) plus renewal loop. | Secondary |
| `route-cert-issuance` | Certificates scoped to an app/database/Kubernetes route. Issuance only. | Optional |
| `mixed` | Weighted blend of the above, weights from config. | Last |
 
Start with `cert-renewal`. Get one scenario fully through driver → metrics → report before adding a second. Do not build all six shells up front.
 
---
 
## Configuration
 
Single YAML file, validated with clear errors on load. Sketch — refine the schema as you go, but keep these concerns separated:
 
```yaml
target:
  proxyAddr: teleport.loadtest.example.com:443
  authAddr: ""                    # optional: dial auth directly to isolate proxy overhead
  cluster: loadtest
  guardrail:
    requireClusterName: loadtest  # refuse to run against anything else
    confirmPhrase: "I am not in production"
 
identity:
  adminIdentityFile: /secrets/loadtest-admin.pem   # seeding only, never in the hot path
 
fixtures:
  userCount: 5000
  userPrefix: stress-
  roles: [stress-access]
  secondFactor: webauthn          # none | totp | webauthn
  keyPool:
    size: 10000
    algorithm: ecdsa              # must match the cluster's signature algorithm suite
 
load:
  scenario: local-login-webauthn
  model: open                     # open | closed
  arrival: poisson                # poisson | uniform
  ramp:
    startRPS: 5
    stepRPS: 5
    stepDuration: 3m
    warmup: 30s
    settle: 15s                   # discarded window after each step change
    maxRPS: 1000
  abort:
    p99LatencyMs: 2000
    errorRatePct: 1.0             # excludes lockouts and generator-limited samples
    throughputDeficitPct: 5       # achieved < 95% of offered
    consecutiveBadSteps: 2
 
observability:
  listen: :9100
  scrape:
    - name: auth
      url: https://teleport-auth.teleport.svc.cluster.local:3000/metrics
      interval: 10s
    - name: proxy
      url: https://teleport-proxy.teleport.svc.cluster.local:3000/metrics
  pprof:
    enabled: true
    targets: [auth]
    captureAtEachStep: true       # 30s CPU profile at steady state per step
 
report:
  outputDir: ./results
  formats: [json, markdown]
```
 
---
 
## Ramp and breaking-point logic
 
1. Run the step plan: warm-up, then each step at a fixed offered rate for `stepDuration`, discarding the `settle` window after every rate change.
2. At the end of each step compute: achieved throughput, error rate by class, latency percentiles from a full-fidelity HDR histogram (not Prometheus buckets — bucket boundaries will round away the answer), and generator health.
3. A step **passes** when error rate, p99, and throughput deficit are all within `abort` thresholds and the generator is not saturated.
4. Stop after `consecutiveBadSteps` failures or on reaching `maxRPS`.
5. The **breaking point** is the highest offered rate whose step passed, plus every subsequent step's data as evidence of the failure mode.
6. Optionally bisect between the last passing and first failing step to tighten the estimate.
## Attribution
 
For the failing steps, correlate the generator's error and latency timeline against server-side signals and emit a ranked list of candidate limiting resources with the evidence for each. Candidates to check: auth CPU saturation, password-hashing cost, backend read/write latency or throttling, gRPC connection and stream limits, proxy-to-auth saturation, rate limiter engagement, audit backend backpressure, Go heap growth or goroutine leak, cache or watcher lag.
 
**Do not hard-code Teleport metric names from memory.** At startup, snapshot the live `/metrics` output from auth and proxy, and build the scrape list and Grafana dashboard from names that actually exist in the target version. Fail loudly with the list of missing names if an expected signal is absent.
 
---
 
## Distributed execution
 
A single pod cannot generate enough TLS handshakes to break a real auth service, and will hit per-IP rate limits first.
 
- Deploy N generator pods via the Helm chart, each assigned `targetRPS / N` and a disjoint slice of the seeded user pool.
- Coordinate steps by **shared wall-clock schedule**: one start timestamp passed to every pod, identical step plans, no leader election, no runtime RPC between pods.
- Each pod writes its HDR histograms and counters to a shared volume or object store on completion. HDR histograms merge losslessly, so aggregation is exact — do not average percentiles across pods.
- The aggregation step is a separate command so a run can be re-analyzed without re-running load.
---
 
## Guardrails (non-negotiable)
 
- Refuse to start unless the connected cluster's name matches `guardrail.requireClusterName` **and** the confirmation phrase is present in the config.
- `authseed` must create only users matching `fixtures.userPrefix`, and `authseed teardown` must delete only users matching that prefix. Never issue an unscoped delete.
- The admin identity is used for seeding only. Assert it is never referenced from any code path inside `Execute`.
- Print a pre-flight summary (target, cluster name, user count, peak offered rate, estimated audit events, estimated duration) and require an explicit confirmation flag for non-interactive runs.
---
 
## Milestones
 
Complete each milestone fully, including its acceptance criteria, before starting the next.
 
**M0 — Skeleton.** Repo layout, config schema with validation, guardrail checks, CLI surface for both binaries.
*Accept:* `authload validate -c scenarios/example.yaml` passes on a good config and fails with a clear message on each of five deliberately broken ones, including a wrong cluster name.
 
**M1 — Fixtures.** `authseed apply` / `authseed teardown`: users, roles, second-factor devices, keypair pool.
*Accept:* seeds 1,000 WebAuthn users against a kind-based Teleport cluster in under two minutes; teardown leaves zero `stress-` users; re-running apply is idempotent.
 
**M2 — First scenario, end to end.** `cert-renewal` plus the open-loop driver, error taxonomy, HDR collection, and a JSON report.
*Accept:* a fixed-rate 2-minute run at 20 RPS reports achieved throughput within 2% of offered, and a deliberately induced failure (auth scaled to zero mid-run) is classified correctly rather than counted as latency.
 
**M3 — Login scenario.** `local-login-webauthn` with soft authenticators and per-phase timing.
*Accept:* phase timings sum to total round-trip within 5%; lockouts and rate-limit responses appear as their own classes in the report; no keypair generation occurs inside `Execute` (prove it with a benchmark or allocation test).
 
**M4 — Ramp and breaking point.** Step plan, abort criteria, knee detection, Markdown report.
*Accept:* against an intentionally undersized cluster (single auth pod, low CPU limit), a ramp converges on a knee and reports the same value within 15% across three consecutive runs.
 
**M5 — Kubernetes deployment.** Helm chart, RBAC, secret handling, multi-pod sharding, shared-clock coordination, aggregation command.
*Accept:* an 8-pod run produces one merged report whose aggregate percentiles match a single-pod run at equivalent total rate within 10%.
 
**M6 — Attribution.** Server-side scraping, pprof capture per step, Grafana dashboard generated from live metric names, ranked limiting-resource output.
*Accept:* for three synthetic bottlenecks you induce deliberately — CPU-limited auth, artificially slowed backend, and an engaged rate limiter — the top-ranked cause is correct in each case.
 
**M7 — Remaining scenarios.** TOTP, `bot-join-renew`, `route-cert-issuance`, `mixed`.
*Accept:* each runs through the same pipeline with no scenario-specific branching in the driver or reporter.
 
---
 
## Reporting
 
Emit both a machine-readable JSON artifact and a human Markdown summary containing:
 
- Run metadata: Teleport version, backend type, auth/proxy replica counts and resource limits, harness version, git SHA, start time, load model.
- The step table: offered rate, achieved rate, p50/p90/p99/p99.9, error counts by class, generator health.
- The declared breaking point, or `generator-limited` / `inconclusive` with the reason.
- Ranked limiting resources with supporting evidence.
- A reproduction command.
`docs/interpreting-results.md` should explain what each failure class usually means and which cluster knob it points at.
 
---
 
## Engineering standards
 
- Go 1.22+, standard project layout, `golangci-lint` clean.
- Unit tests for config validation, error classification, HDR merging, and knee detection. These need no cluster.
- Integration tests run against a kind-based Teleport cluster spun up by the Makefile; they must be skippable via a build tag.
- No `panic` in the load path; a scenario failure degrades one virtual user, never the run.
- Structured logging (`log/slog`), with the hot path logging only at aggregate level — never per request.
- Every non-obvious constraint from the "Critical domain constraints" section gets a code comment citing the reason, so future readers don't "simplify" it away.
---
 
## Start here
 
Read the Teleport source or docs for the exact version in use before writing any client code — confirm the current signatures for user creation, MFA device registration, the web login endpoints, and `GenerateUserCerts`. Then do M0 and M1, and stop for review before M2.
