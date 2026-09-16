package scenario

import (
	"context"
	"errors"
	"net"
	"strings"

	"github.com/gravitational/trace"
)

// lockoutMessage is the exact text Teleport's auth server returns when a
// local user is locked out after too many failed attempts
// (lib/auth/auth.go: MaxFailedAttemptsErrMsg). That constant isn't
// exported outside the main module, so we match on the literal string.
// Domain constraint #2: lockouts must be classified distinctly from
// generic access-denied errors and never folded into the error rate
// that drives abort criteria.
const lockoutMessage = "too many incorrect attempts, please try again later"

// ClassifyError maps an error returned by a Teleport API call to an
// Outcome. This works across both transports this toolkit uses:
//   - gRPC (cert-renewal, M2): the api/client package's interceptor
//     (api/utils/grpc/interceptors.GRPCClientUnaryErrorInterceptor)
//     converts every gRPC status into a github.com/gravitational/trace
//     error wrapped in a RemoteError (which implements Unwrap).
//   - Proxy web API HTTP calls (local-login-webauthn, M3): a non-2xx
//     response's status code and JSON body round-trip through the same
//     github.com/gravitational/trace error types via trace.ReadError,
//     which is what lib/web's handlers write on the server side via
//     trace.WriteError — see internal/scenario/weblogin.go's postJSON.
//
// Either way, errors.As sees through the wrapper here without this
// package needing to import anything from lib/ or the internal
// interceptor package.
//
// Every scenario implementation should route its Execute errors through
// this function so the taxonomy stays consistent across scenarios — it
// must not be reimplemented per scenario.
func ClassifyError(err error) Outcome {
	if err == nil {
		return Success
	}

	if errors.Is(err, context.DeadlineExceeded) {
		return Timeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return Timeout
	}

	var accessDenied *trace.AccessDeniedError
	if errors.As(err, &accessDenied) {
		if strings.Contains(accessDenied.Error(), lockoutMessage) {
			return Lockout
		}
		return ClientError
	}

	var limitExceeded *trace.LimitExceededError
	if errors.As(err, &limitExceeded) {
		return RateLimited
	}

	// Unavailable (e.g. auth scaled to zero, connection refused) is a
	// server/cluster-side failure, not client latency — this is exactly
	// the M2 acceptance scenario of "auth scaled to zero mid-run must be
	// classified correctly rather than counted as latency."
	var connProblem *trace.ConnectionProblemError
	if errors.As(err, &connProblem) {
		return ServerError
	}

	var notFound *trace.NotFoundError
	var alreadyExists *trace.AlreadyExistsError
	var compareFailed *trace.CompareFailedError
	var badParam *trace.BadParameterError
	var notImplemented *trace.NotImplementedError
	switch {
	case errors.As(err, &notFound),
		errors.As(err, &alreadyExists),
		errors.As(err, &compareFailed),
		errors.As(err, &badParam),
		errors.As(err, &notImplemented):
		return ClientError
	}

	// Anything else (Internal, Unknown, a raw non-trace error) is treated
	// as a server-side fault rather than silently absorbed into latency.
	return ServerError
}
