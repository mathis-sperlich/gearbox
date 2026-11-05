package features

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sync/atomic"

	"connectrpc.com/connect"

	"github.com/mathis-sperlich/gearbox/authjwt"
	"github.com/mathis-sperlich/gearbox/connectgear"
)

// NewGate returns an interceptor that gates each procedure in methods (full
// Connect procedure name → feature) on that feature being on for the caller
// in the scope scopeOf reads off the request message. values is the enum's
// generated name→value map (Foo_value); gating on a feature it doesn't define
// is an error.
//
// A gated call is refused with PermissionDenied when there is no
// *authjwt.Claims principal, or the feature is off in the scope (an empty
// scope is off). Unlisted procedures pass through. Unary requests are checked
// once; a streaming handler is checked on every message it receives and may
// not send until the latest one passed. Mount it after
// connectgear.AuthInterceptor so the principal is in place.
func NewGate[F Feature](values map[string]int32, methods map[string]F, scopeOf func(msg any) string) (connect.Interceptor, error) {
	if scopeOf == nil {
		return nil, errors.New("features: gate needs scopeOf")
	}
	e, err := newEnum[F](values)
	if err != nil {
		return nil, err
	}
	for proc, f := range methods {
		if _, known := e[f.String()]; !known {
			return nil, fmt.Errorf("features: %s is gated on unknown feature %s", proc, f.String())
		}
	}
	return &gate[F]{enum: e, methods: maps.Clone(methods), scopeOf: scopeOf}, nil
}

type gate[F Feature] struct {
	enum    enum[F]
	methods map[string]F
	scopeOf func(msg any) string
}

// check returns nil when the call on procedure carrying msg may proceed.
func (g *gate[F]) check(ctx context.Context, procedure string, msg any) error {
	f, gated := g.methods[procedure]
	if !gated {
		return nil
	}
	claims, ok := connectgear.PrincipalFrom(ctx).(*authjwt.Claims)
	if !ok || claims == nil {
		return connect.NewError(connect.CodePermissionDenied, fmt.Errorf("feature %s: no authenticated caller", f))
	}
	decisions, err := g.enum.decisionsOf(claims.Raw)
	if err != nil {
		return connect.NewError(connect.CodePermissionDenied, err)
	}
	if !decisions.Enabled(f, g.scopeOf(msg)) {
		return connect.NewError(connect.CodePermissionDenied, fmt.Errorf("feature %s is not enabled", f))
	}
	return nil
}

func (g *gate[F]) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if !req.Spec().IsClient {
			if err := g.check(ctx, req.Spec().Procedure, req.Any()); err != nil {
				return nil, err
			}
		}
		return next(ctx, req)
	}
}

func (g *gate[F]) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (g *gate[F]) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		if _, gated := g.methods[conn.Spec().Procedure]; !gated {
			return next(ctx, conn)
		}
		return next(ctx, &gatedConn[F]{StreamingHandlerConn: conn, ctx: ctx, g: g})
	}
}

// gatedConn checks every received message. Send is refused until the latest
// received message passed, so a handler that writes before it reads can't
// leak a gated stream.
type gatedConn[F Feature] struct {
	connect.StreamingHandlerConn
	ctx    context.Context
	g      *gate[F]
	passed atomic.Bool
}

func (c *gatedConn[F]) Receive(msg any) error {
	if err := c.StreamingHandlerConn.Receive(msg); err != nil {
		return err
	}
	err := c.g.check(c.ctx, c.Spec().Procedure, msg)
	c.passed.Store(err == nil)
	return err
}

func (c *gatedConn[F]) Send(msg any) error {
	if !c.passed.Load() {
		return connect.NewError(connect.CodePermissionDenied, errors.New("feature gate: no request message has passed yet"))
	}
	return c.StreamingHandlerConn.Send(msg)
}
