package features

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"sync/atomic"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	"github.com/mathis-sperlich/gearbox/authjwt"
	"github.com/mathis-sperlich/gearbox/connectgear"
)

// Gate says which procedures need which feature, and where a request names
// its tenant.
type Gate[F Feature] struct {
	// Enum is the feature enum's generated name→value map (Foo_value).
	Enum map[string]int32
	// Procedures maps a full Connect procedure name (the generated
	// <Service><Method>Procedure constants) to the feature it needs.
	// Procedures not listed pass through.
	Procedures map[string]F
	// ScopeField is the request message field that names the tenant, e.g.
	// "organisation_id". It must be a string field; a message without it is
	// refused.
	ScopeField protoreflect.Name
}

// NewGate returns an interceptor enforcing g.
//
// Early API: the shape of Gate may still change before v1.
//
// A gated call is refused with
// PermissionDenied when there is no *authjwt.Claims principal, or the feature
// is off in the request's scope (an empty scope is off). Unary requests are
// checked once; a streaming handler is checked on every message it receives
// and may not send until the latest one passed. The caller's decisions are
// decoded once per call and handed to the handler through FromContext. Mount
// it after connectgear.AuthInterceptor so the principal is in place.
func NewGate[F Feature](g Gate[F]) (connect.Interceptor, error) {
	if !g.ScopeField.IsValid() {
		return nil, fmt.Errorf("features: gate needs a ScopeField, got %q", g.ScopeField)
	}
	e, err := newEnum[F](g.Enum)
	if err != nil {
		return nil, err
	}
	for proc, f := range g.Procedures {
		if _, known := e[f.String()]; !known {
			return nil, fmt.Errorf("features: %s is gated on unknown feature %s", proc, f.String())
		}
	}
	return &gate[F]{enum: e, procedures: maps.Clone(g.Procedures), scopeField: g.ScopeField}, nil
}

// FromContext returns the caller's decisions, which the gate decoded when the
// call came in, for a handler that checks finer than per procedure. A call
// with no *authjwt.Claims principal or a malformed "features" claim has none.
func FromContext[F Feature](ctx context.Context) (Decisions[F], bool) {
	d, ok := ctx.Value(decisionsKey[F]{}).(Decisions[F])
	return d, ok
}

type decisionsKey[F Feature] struct{}

type gate[F Feature] struct {
	enum       enum[F]
	procedures map[string]F
	scopeField protoreflect.Name
}

// scopeOf reads the tenant off a request message, or says why it can't.
func (g *gate[F]) scopeOf(msg any) (string, error) {
	m, ok := msg.(proto.Message)
	if !ok {
		return "", fmt.Errorf("request is %T, not a proto message", msg)
	}
	field := m.ProtoReflect().Descriptor().Fields().ByName(g.scopeField)
	if field == nil || field.Kind() != protoreflect.StringKind || field.IsList() || field.IsMap() {
		return "", fmt.Errorf("request %s has no singular string field %q", m.ProtoReflect().Descriptor().FullName(), g.scopeField)
	}
	return m.ProtoReflect().Get(field).String(), nil
}

// decode reads the caller's decisions and stores them in ctx. The error says
// why there are none; ctx is unchanged then.
func (g *gate[F]) decode(ctx context.Context) (context.Context, Decisions[F], error) {
	claims, ok := connectgear.PrincipalFrom(ctx).(*authjwt.Claims)
	if !ok || claims == nil {
		return ctx, Decisions[F]{}, errors.New("no authenticated caller")
	}
	d, err := g.enum.decisionsOf(claims.Raw)
	if err != nil {
		return ctx, d, err
	}
	return context.WithValue(ctx, decisionsKey[F]{}, d), d, nil
}

// allow is the gate's decision for f on msg, given what decode found.
func (g *gate[F]) allow(f F, d Decisions[F], decodeErr error, msg any) error {
	if decodeErr != nil {
		return connect.NewError(connect.CodePermissionDenied, fmt.Errorf("feature %s: %w", f, decodeErr))
	}
	scope, err := g.scopeOf(msg)
	if err != nil {
		return connect.NewError(connect.CodePermissionDenied, fmt.Errorf("feature %s: %w", f, err))
	}
	if !d.Enabled(f, scope) {
		return connect.NewError(connect.CodePermissionDenied, fmt.Errorf("feature %s is not enabled", f))
	}
	return nil
}

func (g *gate[F]) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		if req.Spec().IsClient {
			return next(ctx, req)
		}
		ctx, d, err := g.decode(ctx)
		if f, gated := g.procedures[req.Spec().Procedure]; gated {
			if err := g.allow(f, d, err, req.Any()); err != nil {
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
		ctx, d, err := g.decode(ctx)
		f, gated := g.procedures[conn.Spec().Procedure]
		if !gated {
			return next(ctx, conn)
		}
		return next(ctx, &gatedConn[F]{StreamingHandlerConn: conn, g: g, f: f, d: d, decodeErr: err})
	}
}

// gatedConn checks every received message against the decisions decoded
// when the stream opened. Send is refused until the latest received message
// passed, so a handler that writes before it reads can't leak a gated stream.
type gatedConn[F Feature] struct {
	connect.StreamingHandlerConn
	g         *gate[F]
	f         F
	d         Decisions[F]
	decodeErr error
	passed    atomic.Bool
}

func (c *gatedConn[F]) Receive(msg any) error {
	if err := c.StreamingHandlerConn.Receive(msg); err != nil {
		return err
	}
	err := c.g.allow(c.f, c.d, c.decodeErr, msg)
	c.passed.Store(err == nil)
	return err
}

func (c *gatedConn[F]) Send(msg any) error {
	if !c.passed.Load() {
		return connect.NewError(connect.CodePermissionDenied, errors.New("feature gate: no request message has passed yet"))
	}
	return c.StreamingHandlerConn.Send(msg)
}
