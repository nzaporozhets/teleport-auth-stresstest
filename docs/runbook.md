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
2. **Raise the proxy's per-IP rate limits before a ramp, deliberately.**
   Teleport's built-in connection/request limiting will otherwise engage
   long before the auth service itself saturates, and the run will
   measure the limiter instead of the cluster. Raising these limits for a
   load test is part of test setup, not cheating — see domain constraint
   #3 in `docs/methodology.md`. *(Exact Helm values / config keys to set
   are pending M5/M6, once the harness scrapes live `/metrics` to confirm
   which limiter is actually engaging.)*
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

*Not verified end-to-end in this repo's development environment* — the
sandbox this was built in has no Docker/kind/kubectl available, so none
of M1's, M2's, M3's, or M4's acceptance criteria have been run against a
real cluster. Each is checked at the unit level only:
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

Re-run all four milestones' acceptance criteria against a real kind
cluster before relying on any of these claims.
