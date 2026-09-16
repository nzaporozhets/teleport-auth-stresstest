package scenario

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/gravitational/trace"

	"github.com/gravitational/teleport/api/trail"
	"github.com/gravitational/teleport/api/utils/grpc/interceptors"
)

// asClientWouldSeeIt mimics api/utils/grpc/interceptors.GRPCClientUnaryErrorInterceptor
// exactly (same trail.FromGRPC + trace.Unwrap + RemoteError wrapping), so
// these tests exercise the real client-side error shape rather than a
// hand-picked trace.Error.
func asClientWouldSeeIt(code codes.Code, message string) error {
	grpcErr := status.Error(code, message)
	return &interceptors.RemoteError{Err: trace.Unwrap(trail.FromGRPC(grpcErr))}
}

func TestClassifyError(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want Outcome
	}{
		{"nil is success", nil, Success},
		{"lockout", asClientWouldSeeIt(codes.PermissionDenied, lockoutMessage), Lockout},
		{"generic access denied is client error, not lockout", asClientWouldSeeIt(codes.PermissionDenied, "role does not allow this"), ClientError},
		{"resource exhausted is rate limited", asClientWouldSeeIt(codes.ResourceExhausted, "rate limit exceeded"), RateLimited},
		{"unavailable is server error, not latency", asClientWouldSeeIt(codes.Unavailable, "connection refused"), ServerError},
		{"not found is client error", asClientWouldSeeIt(codes.NotFound, "user not found"), ClientError},
		{"invalid argument is client error", asClientWouldSeeIt(codes.InvalidArgument, "bad request"), ClientError},
		{"internal is server error", asClientWouldSeeIt(codes.Internal, "boom"), ServerError},
		{"context deadline exceeded is timeout", context.DeadlineExceeded, Timeout},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := ClassifyError(tc.err)
			if got != tc.want {
				t.Errorf("ClassifyError(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestClassifyError_WrappedDeadlineExceeded(t *testing.T) {
	wrapped := errors.Join(errors.New("dialing"), context.DeadlineExceeded)
	if got := ClassifyError(wrapped); got != Timeout {
		t.Errorf("ClassifyError(wrapped deadline) = %v, want Timeout", got)
	}
}

// TestClassifyError_HTTPPath exercises the other transport this toolkit
// uses (local-login-webauthn, M3): a non-2xx HTTP response whose body
// was written by trace.WriteError (exactly what lib/web's handlers do)
// must classify the same way as the equivalent gRPC error, via
// trace.ReadError. This is the real trace.WriteError/ReadError pair, not
// a hand-picked error.
func TestClassifyError_HTTPPath(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want Outcome
	}{
		{"access denied lockout", trace.AccessDenied("%s", lockoutMessage), Lockout},
		{"access denied generic", trace.AccessDenied("nope"), ClientError},
		{"limit exceeded", trace.LimitExceeded("too fast"), RateLimited},
		{"connection problem", trace.ConnectionProblem(nil, "unavailable"), ServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			trace.WriteError(rec, tc.err)
			got := ClassifyError(trace.ReadError(rec.Code, rec.Body.Bytes()))
			if got != tc.want {
				t.Errorf("status=%d body=%s -> ClassifyError = %v, want %v", rec.Code, rec.Body.String(), got, tc.want)
			}
		})
	}
}
