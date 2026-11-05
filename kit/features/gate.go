package features

import (
	"context"
	"errors"
	"fmt"
	"sync/atomic"

	"connectrpc.com/connect"

	"github.com/mathis-sperlich/gearbox/authjwt"
	"github.com/mathis-sperlich/gearbox/connectgear"
)

// GateConfig configures NewGate.
type GateConfig[F Feature] struct {
	// Registry is the feature enum. Required.
	Registry *Registry[F]

	// Methods maps full Connect procedure names to the feature that must
	// resolve on before the handler runs. A procedure absent from the map
	// passes through ungated; a mapped one fails CLOSED — no decisions, no
	// scope, or a feature that resolves off all return PermissionDenied.
	// Use generated procedure constants and enum values so a typo on either
	// side is a build error. NewGate refuses a map naming an unknown feature.
	Methods map[string]F

	// ScopeOf extracts the tenant scope a call acts in, from the procedure
	// and its request message (for a stream, from each received message).
	// ok=false or an empty scope denies a gated call. nil means the app
	// doesn't tenant: every check consults the global bucket only.
	ScopeOf func(ctx context.Context, procedure string, msg any) (scope string, ok bool)

	// Canonical maps a scope from ScopeOf to the form claim buckets are keyed
	// by (UUIDScope for UUID tenants); ok=false denies. nil accepts the scope
	// as is. Either way, an empty scope and GlobalBucket are refused: a
	// request can never select the global bucket as its tenant.
	Canonical func(scope string) (string, bool)

	// DecisionsOf returns the caller's decisions; ok=false means no
	// authenticated caller and denies a gated call. nil reads the principal
	// connectgear's AuthInterceptor stored and parses its claims when it is
	// an *authjwt.Claims (any other principal has no decisions).
	DecisionsOf func(ctx context.Context) (Decisions, bool)

	// Refuse builds the error for a gated call whose feature resolved off,
	// e.g. to attach error details. nil returns PermissionDenied.
	Refuse func(ctx context.Context, procedure string, f F, scope string) *connect.Error
}

// Gate is a fail-closed feature gate over Connect procedures.
type Gate[F Feature] struct {
	reg         *Registry[F]
	methods     map[string]F
	scopeOf     func(context.Context, string, any) (string, bool)
	canonical   func(string) (string, bool)
	decisionsOf func(context.Context) (Decisions, bool)
	refuse      func(context.Context, string, F, string) *connect.Error
}

// NewGate validates cfg and builds a Gate. Methods is copied, so later edits
// to the map don't change the gate.
func NewGate[F Feature](cfg GateConfig[F]) (*Gate[F], error) {
	if cfg.Registry == nil {
		return nil, errors.New("features: gate needs a registry")
	}
	g := &Gate[F]{
		reg:         cfg.Registry,
		methods:     make(map[string]F, len(cfg.Methods)),
		scopeOf:     cfg.ScopeOf,
		canonical:   cfg.Canonical,
		decisionsOf: cfg.DecisionsOf,
		refuse:      cfg.Refuse,
	}
	for proc, f := range cfg.Methods {
		if !cfg.Registry.Known(f) {
			return nil, fmt.Errorf("features: %s is gated on unknown feature %s", proc, f.String())
		}
		g.methods[proc] = f
	}
	if g.decisionsOf == nil {
		g.decisionsOf = principalDecisions
	}
	return g, nil
}

func principalDecisions(ctx context.Context) (Decisions, bool) {
	c, ok := connectgear.PrincipalFrom(ctx).(*authjwt.Claims)
	if !ok || c == nil {
		return nil, false
	}
	return FromClaims(c.Raw), true
}

// resolved is what Has reads: the caller's decisions and where it acts.
type resolved struct {
	d      Decisions
	scope  string // canonical; "" = none
	global bool   // the app doesn't tenant
}

func (r resolved) enabled(name string) bool {
	if r.global {
		return r.d.EnabledGlobally(name)
	}
	return r.d.Enabled(name, r.scope)
}

type resolvedKey struct{}

// Has reports whether f is on for the call in ctx. It reads what the Gate's
// interceptor resolved; with no gate in the chain, no authenticated caller,
// or no scope it is false. In a stream handler the scope lives on messages,
// so call Gate.WithScope first.
func Has[F Feature](ctx context.Context, f F) bool {
	r, ok := ctx.Value(resolvedKey{}).(resolved)
	return ok && r.enabled(f.String())
}

// WithScope returns ctx with the caller's decisions bound to scope, for Has.
// The scope goes through Canonical; a refused scope leaves Has false.
func (g *Gate[F]) WithScope(ctx context.Context, scope string) context.Context {
	r, ok := ctx.Value(resolvedKey{}).(resolved)
	if !ok {
		d, authed := g.decisionsOf(ctx)
		if !authed {
			return ctx
		}
		r = resolved{d: d, global: g.scopeOf == nil}
	}
	r.scope, _ = g.canonicalScope(scope)
	return context.WithValue(ctx, resolvedKey{}, r)
}

func (g *Gate[F]) canonicalScope(scope string) (string, bool) {
	if g.canonical != nil {
		var ok bool
		if scope, ok = g.canonical(scope); !ok {
			return "", false
		}
	}
	if scope == "" || scope == GlobalBucket {
		return "", false
	}
	return scope, true
}

// resolve computes what the call may see; it never refuses.
func (g *Gate[F]) resolve(ctx context.Context, procedure string, msg any) (resolved, bool) {
	d, ok := g.decisionsOf(ctx)
	if !ok {
		return resolved{}, false
	}
	r := resolved{d: d, global: g.scopeOf == nil}
	if g.scopeOf != nil {
		if s, ok := g.scopeOf(ctx, procedure, msg); ok {
			r.scope, _ = g.canonicalScope(s)
		}
	}
	return r, true
}

// check returns nil to proceed or a Connect error, plus what was resolved
// for Has.
func (g *Gate[F]) check(ctx context.Context, procedure string, msg any) (resolved, bool, error) {
	r, authed := g.resolve(ctx, procedure, msg)
	f, gated := g.methods[procedure]
	if !gated {
		return r, authed, nil
	}
	if !authed {
		return r, authed, connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("feature %s: no authenticated caller", f.String()))
	}
	if !r.global && r.scope == "" {
		return r, authed, connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("feature %s: request names no scope", f.String()))
	}
	if !r.enabled(f.String()) {
		if g.refuse != nil {
			if err := g.refuse(ctx, procedure, f, r.scope); err != nil {
				return r, authed, err
			}
		}
		return r, authed, connect.NewError(connect.CodePermissionDenied,
			fmt.Errorf("feature %s is not enabled", f.String()))
	}
	return r, authed, nil
}

// Interceptor gates unary calls on the request message and streaming
// handlers on every received message (the scope lives on the message, so the
// decision can only be made once it has arrived). List it after
// connectgear.AuthInterceptor so the principal is in place. Unary handlers
// can call Has; client calls pass through.
func (g *Gate[F]) Interceptor() connect.Interceptor { return gateInterceptor[F]{g} }

type gateInterceptor[F Feature] struct{ g *Gate[F] }

func (i gateInterceptor[F]) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if req.Spec().IsClient {
			return next(ctx, req)
		}
		r, authed, err := i.g.check(ctx, req.Spec().Procedure, req.Any())
		if err != nil {
			return nil, err
		}
		if authed {
			ctx = context.WithValue(ctx, resolvedKey{}, r)
		}
		return next(ctx, req)
	}
}

func (i gateInterceptor[F]) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler refuses an unauthenticated caller of a gated stream
// up front, then checks every received message. Until one has passed, Send
// is refused too, so a handler that writes before it reads can't leak a
// gated stream.
func (i gateInterceptor[F]) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		_, gated := i.g.methods[conn.Spec().Procedure]
		d, authed := i.g.decisionsOf(ctx)
		if authed {
			// No scope yet: Has stays false until the handler calls WithScope
			// (or always answers globally for an untenanted app).
			ctx = context.WithValue(ctx, resolvedKey{}, resolved{d: d, global: i.g.scopeOf == nil})
		} else if gated {
			_, _, err := i.g.check(ctx, conn.Spec().Procedure, nil)
			return err
		}
		gc := &gatedConn[F]{StreamingHandlerConn: conn, ctx: ctx, g: i.g}
		gc.passed.Store(!gated)
		return next(ctx, gc)
	}
}

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
	if _, _, err := c.g.check(c.ctx, c.Spec().Procedure, msg); err != nil {
		c.passed.Store(false)
		return err
	}
	c.passed.Store(true)
	return nil
}

func (c *gatedConn[F]) Send(msg any) error {
	if !c.passed.Load() {
		return connect.NewError(connect.CodePermissionDenied,
			errors.New("feature gate: no request message has been checked yet"))
	}
	return c.StreamingHandlerConn.Send(msg)
}
