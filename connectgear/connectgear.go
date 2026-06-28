// Package connectgear glues gearbox into a Connect-RPC server. The consumer
// owns the protos, the generated service, and the interceptors (auth,
// protovalidate); this package supplies the two pieces every handler needs:
// an error mapper and the Principal ctx plumbing.
//
// Auth interceptor stores the identity; handlers pass it to gearbox:
//
//	ctx = connectgear.WithPrincipal(ctx, claims)            // in your interceptor
//	resp, err := gearbox.Run(ctx, eng, connectgear.PrincipalFrom(ctx), orders.Pay, req.Msg.GetId(), req.Msg)
//	if err != nil { return nil, connectgear.Err(err) }
//	return connect.NewResponse(resp), nil
package connectgear

import (
	"context"
	"errors"

	"connectrpc.com/connect"

	"github.com/mathis-sperlich/gearbox"
)

type principalKey struct{}

// WithPrincipal stores the caller identity on the context — call from your auth
// interceptor after verifying credentials.
func WithPrincipal(ctx context.Context, p gearbox.Principal) context.Context {
	return context.WithValue(ctx, principalKey{}, p)
}

// PrincipalFrom returns the identity stored by WithPrincipal, or nil.
func PrincipalFrom(ctx context.Context) gearbox.Principal {
	return ctx.Value(principalKey{})
}

// Err maps a gearbox error to a *connect.Error so clients get the right code
// (409 failed_precondition for an illegal transition, 404, 403, 401). Unmapped
// errors become CodeInternal with the message withheld — internal detail can
// carry SQL fragments. Nil passes through.
func Err(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, gearbox.ErrInvalidTransition):
		return connect.NewError(connect.CodeFailedPrecondition, err)
	case errors.Is(err, gearbox.ErrEntityNotFound):
		return connect.NewError(connect.CodeNotFound, err)
	case errors.Is(err, gearbox.ErrBadSelector):
		return connect.NewError(connect.CodeInvalidArgument, err)
	case errors.Is(err, gearbox.ErrUnauthorized), errors.Is(err, gearbox.ErrSaveBlocked):
		return connect.NewError(connect.CodePermissionDenied, err)
	case errors.Is(err, gearbox.ErrUnauthenticated):
		return connect.NewError(connect.CodeUnauthenticated, err)
	default:
		return connect.NewError(connect.CodeInternal, errors.New("internal error"))
	}
}
