# Methodology

This document tracks how each critical domain constraint from the project
spec is handled, and where in the code. It is updated as each milestone
lands; entries marked "pending" are not yet implemented.

## 1. TOTP cannot be replayed

WebAuthn is the primary login scenario, implemented (M3) as
`internal/scenario.LocalLoginWebAuthn`; TOTP (`local-login-totp`) is
secondary and capped at roughly one login per user per ~30s window —
*pending: M7*. The soft WebAuthn and TOTP authenticators (used for both
seeding, M1, and login load, M3) live in
`internal/identity/webauthn_soft.go` and `internal/identity/totp_soft.go`;
both are verified in tests against the real `github.com/go-webauthn/webauthn`
(the same library Teleport's server uses) and `github.com/pquerna/otp`
libraries, not just round-tripped against their own encoder.
`internal/scenario/locallogin_test.go` goes further: its fake proxy
server cryptographically verifies every assertion `Execute` sends using
that same real library and a real, independently-registered credential —
so the test is checking Teleport-compatibility, not just internal
self-consistency.

## 2. Account lockout

`internal/scenario.ClassifyError` distinguishes a lockout
(`AccessDeniedError` whose message matches Teleport's exact lockout text,
`lib/auth/auth.go`'s `MaxFailedAttemptsErrMsg`) from a generic
`ClientError` access-denial, mapping to the dedicated `Lockout` outcome,
across both transports this toolkit uses (gRPC, M2; the proxy web API's
`trace.WriteError`/`ReadError` HTTP convention, M3 — see
`internal/scenario/locallogin_test.go`'s `TestLocalLoginWebAuthn_Lockout`).
`collect.Snapshot.ErrorRatePct` currently counts every non-`Success`
outcome, including `Lockout`, in the error rate — *excluding* lockouts
from the rate that drives abort criteria, and retiring a locked-out user
from the pool, are ramp-level concerns and remain *pending: M4* (the
`collect`/`ramp` split needed to do that scopes to the ramp controller,
which doesn't exist yet).

## 3. Built-in per-IP rate limiting

Implemented (M2/M3): `internal/scenario.ClassifyError` maps a
`LimitExceededError` (gRPC `ResourceExhausted`, or HTTP 429 via
`trace.ReadError`) to the dedicated `RateLimited` outcome, distinct from
generic server errors, for both transports. The runbook
(`docs/runbook.md`) documents which cluster settings to raise before a
ramp, and states that raising them is part of test setup, not cheating.

## 4. Client-side key generation is not server work

Implemented (M1/M3). `fixtures.keyPool` (see `internal/config`)
pre-generates a pool of keypairs during `authseed apply`
(`internal/identity/keypool.go`, `seed.go`) and persists it, private keys
included, to `fixtures.statePath` (`internal/identity/fixtures.go`) so a
later `authload` process can load it once and draw from it in the hot
path without ever generating a key inline. Every implemented scenario
(`CertRenewal`, `LocalLoginWebAuthn`) draws keys via `KeyPool.At(idx)` in
`Execute`. Proof, per the M3 acceptance criterion: `internal/identity`
has a process-wide `KeyGenCount`/`ResetKeyGenCount` counter incremented
inside `GenerateKeyPair` itself; `TestLocalLoginWebAuthn_NoHotPathKeygen`
resets it, runs `Execute` 50 times, and asserts it's still zero. This is
a direct proof, not an allocation-count proxy — chosen because
allocation counts are noisy (TLS buffers, JSON encoding) and wouldn't
unambiguously distinguish "no keygen" from "a cheap keygen we didn't
notice."

## 5. Audit event volume

Every login writes audit events. The report must estimate and state total
events emitted; the runbook must tell operators to check audit backend
headroom before a long ramp. *Pending: M4/M6 (report + runbook).*

## 6. Coordinated omission

Implemented (M2): `internal/driver.RunOpenLoop` schedules calls at a
fixed target rate (Poisson or uniform arrival) and never waits for a
previous call to finish before starting the next — latency
(`Sample.OpenLoopLatency`) is measured from the intended arrival time,
not from when a goroutine actually became free. `RunClosedLoop` exists
for comparison only; `cmd/authload run` refuses `load.model: closed` for
now (the loop itself is implemented and tested, just not wired into the
CLI yet) so nothing can accidentally ship a closed-loop result unlabeled.
The report's `meta.loadModel`/`meta.arrival` fields record which was
used.

## 7. Generator saturation

The generator continuously samples its own CPU, goroutine count, open file
descriptors, and ephemeral port usage. If any threshold is crossed, the run
is marked `generator-limited` and no cluster breaking point is reported.
*Pending: M4 (ramp package).*

## Guardrails (implemented, M0)

- `authload validate` / `authseed validate` refuse a config unless
  `target.guardrail.requireClusterName` is set, matches `target.cluster`,
  and `target.guardrail.confirmPhrase` exactly equals the literal phrase
  `"I am not in production"` (`internal/config/validate.go`).
- At connect time (M1+), `Config.CheckLiveClusterName` additionally refuses
  to proceed unless the *actually connected* cluster's name matches
  `requireClusterName` — the config-time check above is a self-consistency
  check on the file, not a substitute for it.
- `authseed` scopes every create/delete to `fixtures.userPrefix` and never
  issues an unscoped delete (M1).
- The admin identity (`identity.adminIdentityFile`) is used for seeding
  only; it must never be referenced from any code path inside a
  `Scenario.Execute` (M1+ asserted by code review / M3 test).

## M1 implementation notes

- **MFA device registration has no admin-side shortcut.** There is no
  `UpsertMFADevice`-style RPC; registering a device for a brand-new user
  requires the same token ceremony a real user would go through
  (`CreateResetPasswordToken` → `CreateRegisterChallenge` →
  `ChangeUserAuthentication`), all driven over the *admin* gRPC
  connection (`internal/identity/seed.go`). This is still "seeding only"
  per the guardrails — it never touches a scenario's `Execute`.
- **Idempotency is convergent, not a no-op.** `UpsertUser`/`UpsertRole`
  are true replace-by-name and safe to re-run. The MFA/password ceremony
  is not: every `authseed apply` re-run rotates each user's password and
  WebAuthn/TOTP device. Re-running is safe (ends in an equally-valid
  state) but not free for a large `userCount`.
- **`fixtures.statePath` is a config field not in the original sketch**
  in instructions.md — added because seeded credentials (passwords, MFA
  secrets, keypair pool private keys) have to be handed from `authseed`
  to `authload` somehow, and the original schema had nowhere for that.

## M2 implementation notes

- **`cert-renewal` bootstraps via impersonation, then self-renews.** A
  bare local user has no certificate to renew; `internal/scenario.CertRenewal.Setup`
  uses `env.Admin` (the admin identity, only during `Setup`, never
  `Execute`) to call `GenerateUserCerts` once per virtual user with
  `Username` set to the *seeded* user, not the admin's own identity —
  Teleport treats this as impersonation
  (`lib/auth/auth_with_roles.go`'s `generateUserCerts`). **This requires
  a cluster-side RBAC grant**: the admin identity's role needs an
  `allow.impersonate` rule covering `fixtures.roles`/the seeded users, or
  it needs the builtin `Admin` role. There is no way to check or satisfy
  this from the config file — document it as a precondition, and expect
  `authload run`'s scenario `Setup` to fail with a clear `AccessDenied`
  if it's missing.
- **Admin Action MFA can make bootstrap impractical at scale.** If the
  cluster enforces `second_factor: webauthn` without allowing TOTP,
  Teleport requires a fresh MFA response on every impersonation call
  *unless* the caller is a Machine ID bot identity (or is itself
  impersonated by one) — `lib/authz/permissions.go`. **Recommendation:
  `identity.adminIdentityFile` should be a Machine ID bot identity**, not
  a plain local-admin identity file, specifically so a `userCount` in the
  thousands doesn't mean thousands of MFA ceremonies during
  `authseed apply`'s device-registration flow or `cert-renewal`'s
  bootstrap. *(Worth revisiting for M1's MFA-registration ceremony too —
  it uses token-based calls that skip this check per-call, so it's not
  affected, but the same bot-identity recommendation still simplifies
  cluster setup.)*
- **Self-renewal never needs MFA and has a real TTL ceiling.** When
  `Username` equals the caller's own identity, no MFA/admin-action check
  applies. But the server clamps `Expires` to the original bootstrap
  certificate's expiry for a plain (non-bot, non-role-impersonated)
  identity — it does not extend on renewal. `CertRenewal` requests a
  fresh 30-minute TTL on every call anyway (that's the realistic
  request shape; only the *result* is capped) and bootstraps with a
  12-hour TTL, which must exceed however long a run using this scenario
  will last, or renewals will start failing with
  `client.ErrClientCredentialsHaveExpired` near the end of a long run.
- **One long-lived connection per virtual identity, not one per call.**
  Matches `lib/tbot`'s own renewal pattern: `Setup` opens
  `len(seeded users)` (capped by key pool size) `*apiclient.Client`
  connections, each authenticated with its own bootstrap credential via
  `apiclient.KeyPair`, and keeps them open for the scenario's lifetime.
  `Execute` reuses one round-robin via an atomic counter — concurrent
  RPCs on the same `*apiclient.Client` are safe (gRPC multiplexes
  streams), so this doesn't limit concurrency.

## M3 implementation notes

- **The proxy web login wire types are not importable.** `client.MFAChallengeRequest`,
  `client.AuthenticateSSHUserRequest`, `client.UserPublicKeys`, and
  `authclient.SSHLoginResponse` all live in `lib/client`/`lib/auth/authclient`
  — outside the `api/` module boundary, same reason M1 avoided
  `lib/auth/mocku2f`. `internal/scenario/weblogin.go` re-declares just
  the fields this toolkit sends/reads, with JSON tags verified field-by-field
  against the pinned source, rather than importing anything from `lib/`.
- **The WebAuthn sub-fields on this HTTP path are a different Go type
  than M1's gRPC-based registration path, but the same underlying spec
  shape.** Registration (M1, admin gRPC) uses `api/types/webauthn`
  protobuf types. Login (M3, proxy HTTP) uses Teleport's own
  `lib/auth/webauthntypes` — itself a JSON-safe clone of
  `github.com/go-webauthn/webauthn/protocol`, already a dependency since
  M1's tests. `SoftWebAuthnDevice.SignAssertion` still takes the
  protobuf-shaped `webauthnpb.CredentialAssertion` (a cheap, un-generated
  struct — building one is not "keygen" and is fine in the hot path);
  `internal/scenario/locallogin.go` converts its output into the HTTP
  wire shape rather than changing `SignAssertion`'s signature, so M1's
  tests keep covering it unmodified.
- **One real encoding inconsistency to watch for**: the begin-response's
  `challenge` field is a plain `[]byte` (Go's default: padded
  `base64.StdEncoding`), while the WebAuthn-spec `clientDataJSON.challenge`
  field `SoftWebAuthnDevice` builds from those same decoded bytes is
  `base64.RawURLEncoding` (unpadded, URL-safe) — two different encodings
  for the same bytes at two different boundaries. Declaring the wire
  struct field as plain `[]byte` (not a custom base64url type) is what
  makes `encoding/json` handle the first hop correctly with no manual
  code; `buildClientDataJSON` (M1) already handles the second hop
  correctly since it always took raw bytes as input.
- **`trace.ReadError`/`trace.WriteError` mean one error taxonomy serves
  both transports.** Teleport's HTTP handlers write errors with
  `trace.WriteError`, which round-trips the exact same
  `github.com/gravitational/trace` error types M2's gRPC path already
  produces. `postJSON` (`weblogin.go`) converts a non-2xx response via
  `trace.ReadError(status, body)`, and the *existing* `ClassifyError`
  handles the result unchanged — confirmed in
  `classify_test.go`'s `TestClassifyError_HTTPPath` before writing any
  scenario code, and exercised for real in
  `locallogin_test.go`'s lockout/rate-limit/scaled-to-zero tests against
  a fake proxy built with `trace.WriteError` itself.
- **`target.insecureSkipVerify` is a config field not in the original
  sketch** — added because this HTTP path needs its own TLS trust
  decision (self-signed certs on a disposable kind/dev cluster), separate
  from however the gRPC clients trust the cluster.

## Teleport version pin

Pinned to Teleport `v17.7.29` (commit `f11aeb122c9351028dd6e8c06b48094ab0dc91ee`).
The `github.com/gravitational/teleport/api` Go module is pinned to this
exact commit via a pseudo-version in `go.mod`
(`v0.0.0-20260909235331-f11aeb122c93`), following the same pattern
Teleport's own external consumers (e.g. `teleport-plugins`) use, since
that module doesn't publish a `/vNN`-suffixed module path for major
versions beyond v1. The main `github.com/gravitational/teleport` module
(`lib/...`) is deliberately *not* a dependency: it's AGPL-licensed,
outside the api/ compatibility boundary, and everything this toolkit
needs from it (the soft WebAuthn/TOTP authenticators) is reimplemented
against the public `api/types/webauthn` wire types instead of importing
`lib/auth/mocku2f` — see `internal/identity/webauthn_soft.go`. All client
code in this repo is written against the source at the pinned commit, not
against training-data assumptions about older Teleport versions — see the
file:line citations in the code and in commit research where an API
signature is non-obvious. Building against this pin requires Go ≥1.25.14
(the `api` module's own `go.mod` minimum) and
`github.com/charlievieth/strcase` ≥v0.0.6 (older versions panic at init
against Go's newer Unicode tables) — see docs/runbook.md.
