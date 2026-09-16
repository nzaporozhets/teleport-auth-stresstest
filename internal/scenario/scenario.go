// Package scenario defines the Scenario interface every workload
// implements, so the driver, collector, and ramp controller stay
// workload-agnostic (see instructions.md "Architecture").
package scenario

import (
	"context"

	"teleport-auth-stress/internal/config"
	"teleport-auth-stress/internal/identity"
)

// Outcome classifies the result of a single Execute call. Keep lockout and
// rate-limit distinct from generic client/server errors: they drive
// separate reporting and must never be folded into the error rate that
// feeds abort criteria (instructions.md domain constraints #2 and #3).
type Outcome int

const (
	Success Outcome = iota
	Lockout
	RateLimited
	Timeout
	ServerError
	ClientError
)

func (o Outcome) String() string {
	switch o {
	case Success:
		return "success"
	case Lockout:
		return "lockout"
	case RateLimited:
		return "rate-limited"
	case Timeout:
		return "timeout"
	case ServerError:
		return "server-error"
	case ClientError:
		return "client-error"
	default:
		return "unknown"
	}
}

// ParseOutcome is the inverse of String, for reading back an Outcome
// persisted as its string form (e.g. internal/collect.RawData, written
// by one pod and read by the aggregation command, M5).
func ParseOutcome(s string) (Outcome, bool) {
	switch s {
	case "success":
		return Success, true
	case "lockout":
		return Lockout, true
	case "rate-limited":
		return RateLimited, true
	case "timeout":
		return Timeout, true
	case "server-error":
		return ServerError, true
	case "client-error":
		return ClientError, true
	default:
		return 0, false
	}
}

// Phase is a named sub-timing within one Execute call, e.g. dial, tls,
// password, mfa, cert-issue.
type Phase struct {
	Name     string
	Duration int64 // nanoseconds; avoids importing time in the hot-path result type
}

// Result is what one Execute call reports.
type Result struct {
	Phases  []Phase
	Outcome Outcome
	Bytes   int64
}

// Env carries whatever a Scenario's Setup needs to build its per-process
// state. Admin is set only for the duration of Setup — the guardrails
// require it never be referenced from any code path inside Execute (a
// Scenario implementation that stashes it in a field and uses it later
// would violate that; Setup should extract only what Execute needs, e.g.
// already-issued per-identity credentials, and let Admin go out of
// scope).
type Env struct {
	Config   *config.Config
	Admin    *identity.AdminClient
	Fixtures *identity.FixtureState
}

// Scenario is a workload the driver can run at a target rate. Execute must
// be safe for concurrent use, must not allocate expensive crypto material
// (instructions.md domain constraint #4), and must never panic — a
// scenario failure degrades one virtual user, never the whole run.
type Scenario interface {
	Name() string
	// Setup runs once per process before load starts.
	Setup(ctx context.Context, env *Env) error
	// Execute performs exactly one logical operation and returns
	// per-phase timings.
	Execute(ctx context.Context) (Result, error)
	Teardown(ctx context.Context) error
}
