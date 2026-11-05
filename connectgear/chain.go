package connectgear

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"runtime/debug"

	"connectrpc.com/connect"

	"github.com/mathis-sperlich/gearbox"
	"github.com/mathis-sperlich/gearbox/authjwt"
)

// Authenticator is the single auth decision for a server call: request
// headers in, the verified Principal (or a refusal) out. The auth interceptor
// calls it for unary calls and streams alike, so both paths share one policy.
// spec says which procedure and stream type is being called, for an
// Authenticator that refuses some credentials on streams. A returned
// *connect.Error reaches the client as is; any other error goes through Err
// (gearbox.ErrUnauthenticated → unauthenticated, anything else → internal
// with the message withheld).
type Authenticator func(ctx context.Context, spec connect.Spec, header http.Header) (gearbox.Principal, error)

// Bearer is an Authenticator that verifies an HS256 "Authorization: Bearer"
// token with v and yields its *authjwt.Claims as the Principal.
func Bearer(v *authjwt.Verifier) Authenticator {
	return func(_ context.Context, _ connect.Spec, h http.Header) (gearbox.Principal, error) {
		c, err := v.VerifyBearer(h.Get("Authorization"))
		if err != nil {
			return nil, connect.NewError(connect.CodeUnauthenticated, err)
		}
		return c, nil
	}
}

// AuthOption configures AuthInterceptor.
type AuthOption func(*authInterceptor)

// PublicProcedures lets the named unary procedures (full names, e.g.
// "/acme.v1.OrderService/ListPrices") through without credentials. It never
// applies to a stream: a stream always authenticates (fail closed).
func PublicProcedures(procedures ...string) AuthOption {
	return func(i *authInterceptor) {
		for _, p := range procedures {
			i.public[p] = true
		}
	}
}

// AuthInterceptor authenticates every unary call and every streaming handler
// through authn and stores the Principal with WithPrincipal, so handlers read
// it with PrincipalFrom. A refused call never reaches the handler. Client-side
// calls pass through untouched.
func AuthInterceptor(authn Authenticator, opts ...AuthOption) connect.Interceptor {
	i := &authInterceptor{authn: authn, public: map[string]bool{}}
	for _, o := range opts {
		o(i)
	}
	return i
}

type authInterceptor struct {
	authn  Authenticator
	public map[string]bool
}

func (i *authInterceptor) authenticate(ctx context.Context, spec connect.Spec, h http.Header) (context.Context, error) {
	p, err := i.authn(ctx, spec, h)
	if err != nil {
		var ce *connect.Error
		if errors.As(err, &ce) {
			return nil, ce
		}
		return nil, Err(err)
	}
	if p == nil {
		// An Authenticator that says neither yes nor no is a refusal.
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("no principal"))
	}
	return WithPrincipal(ctx, p), nil
}

func (i *authInterceptor) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		spec := req.Spec()
		if spec.IsClient || i.public[spec.Procedure] {
			return next(ctx, req)
		}
		ctx, err := i.authenticate(ctx, spec, req.Header())
		if err != nil {
			return nil, err
		}
		return next(ctx, req)
	}
}

func (i *authInterceptor) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler never consults PublicProcedures: a stream always needs
// credentials.
func (i *authInterceptor) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		ctx, err := i.authenticate(ctx, conn.Spec(), conn.RequestHeader())
		if err != nil {
			return err
		}
		return next(ctx, conn)
	}
}

// DefaultMaxRequestBytes is the most of a request Options lets a handler read.
// connect-go reads and decodes the body before any interceptor runs, so
// without a limit anyone could make the server buffer a request of any size.
// A larger one is refused as resource_exhausted with no other work.
const DefaultMaxRequestBytes = 8 << 20

// recoverPanics turns a handler panic into CodeInternal with the panic
// withheld from the client (its text can carry SQL or secrets), and logs the
// value and stack with slog.ErrorContext.
func recoverPanics() connect.HandlerOption {
	return connect.WithRecover(func(ctx context.Context, spec connect.Spec, _ http.Header, p any) error {
		slog.ErrorContext(ctx, "connectgear: handler panicked", "procedure", spec.Procedure, "panic", p, "stack", string(debug.Stack()))
		return connect.NewError(connect.CodeInternal, errors.New("internal error"))
	})
}

// Options is the option every handler of a service is mounted with: the
// interceptors in the order given (first is outermost), a
// DefaultMaxRequestBytes read limit, and panic recovery innermost, so a panic
// comes back through the interceptors as an ordinary internal error. A service
// with larger legitimate requests mounts with its own connect.WithReadMaxBytes
// after Options, which wins.
//
//	opts := connectgear.Options(
//		connectgear.AuthInterceptor(connectgear.Bearer(v), connectgear.PublicProcedures(pricesProcedure)),
//	)
//	mux.Handle(ordersv1connect.NewOrderServiceHandler(svc, opts))
func Options(interceptors ...connect.Interceptor) connect.HandlerOption {
	return connect.WithHandlerOptions(
		connect.WithInterceptors(interceptors...),
		connect.WithReadMaxBytes(DefaultMaxRequestBytes),
		recoverPanics(),
	)
}
