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

// Gate is a fail-closed feature gate over Connect procedures.
type Gate[F Feature] struct {
	methods map[string]F
	scopeOf func(msg any) string
}

// NewGate gates each procedure in methods (full Connect procedure name →
// feature) on its feature being on for the caller in the scope scopeOf reads
// off the request message. A gated call is refused with PermissionDenied when
// there is no *authjwt.Claims principal, or the feature is off in the scope
// (an empty scope is off). Unlisted procedures pass through. methods is
// copied; naming a feature reg doesn't define is an error.
func NewGate[F Feature](reg *Registry[F], methods map[string]F, scopeOf func(msg any) string) (*Gate[F], error) {
	if reg == nil || scopeOf == nil {
		return nil, errors.New("features: gate needs a registry and scopeOf")
	}
	for proc, f := range methods {
		if !reg.Known(f) {
			return nil, fmt.Errorf("features: %s is gated on unknown feature %s", proc, f.String())
		}
	}
	return &Gate[F]{methods: maps.Clone(methods), scopeOf: scopeOf}, nil
}

// check returns nil when the call on procedure carrying msg may proceed.
func (g *Gate[F]) check(ctx context.Context, procedure string, msg any) error {
	f, gated := g.methods[procedure]
	if !gated {
		return nil
	}
	claims, ok := connectgear.PrincipalFrom(ctx).(*authjwt.Claims)
	if !ok || claims == nil {
		return connect.NewError(connect.CodePermissionDenied, fmt.Errorf("feature %s: no authenticated caller", f))
	}
	decisions, err := FromClaims(claims.Raw)
	if err != nil {
		return connect.NewError(connect.CodePermissionDenied, err)
	}
	if !decisions.Enabled(f, g.scopeOf(msg)) {
		return connect.NewError(connect.CodePermissionDenied, fmt.Errorf("feature %s is not enabled", f))
	}
	return nil
}

// Interceptor checks unary requests, and every message a streaming handler
// receives (the scope lives on the message). List it after
// connectgear.AuthInterceptor so the principal is in place. Client calls pass
// through.
func (g *Gate[F]) Interceptor() connect.Interceptor { return gateInterceptor[F]{g} }

type gateInterceptor[F Feature] struct{ g *Gate[F] }

func (i gateInterceptor[F]) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if !req.Spec().IsClient {
			if err := i.g.check(ctx, req.Spec().Procedure, req.Any()); err != nil {
				return nil, err
			}
		}
		return next(ctx, req)
	}
}

func (i gateInterceptor[F]) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

func (i gateInterceptor[F]) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		if _, gated := i.g.methods[conn.Spec().Procedure]; !gated {
			return next(ctx, conn)
		}
		return next(ctx, &gatedConn[F]{StreamingHandlerConn: conn, ctx: ctx, g: i.g})
	}
}

// gatedConn checks every received message. Send is refused until the latest
// received message passed, so a handler that writes before it reads can't
// leak a gated stream.
type gatedConn[F Feature] struct {
	connect.StreamingHandlerConn
	ctx    context.Context
	g      *Gate[F]
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
