package gearbox

import "errors"

// ErrInvalidTransition — the entity's current status isn't in the action's From
// set. Map to HTTP 409 / Connect CodeFailedPrecondition.
var ErrInvalidTransition = errors.New("gearbox: invalid transition")

// ErrEntityNotFound — Load found no row. Map to 404 / CodeNotFound.
var ErrEntityNotFound = errors.New("gearbox: entity not found")

// ErrSaveBlocked — Save reported zero rows affected. The canonical cause is a
// database tenancy denial (e.g. an RLS UPDATE policy silently filtering the
// row): the caller could load the row but not write it. Map to 403 /
// CodePermissionDenied.
var ErrSaveBlocked = errors.New("gearbox: save affected zero rows (likely a tenancy/RLS denial)")

// ErrBadSelector — a RunAll selector is nil, selects nothing, or sets both id
// and ids. Normally caught earlier by protovalidate; this is the engine-side
// hard fail. Map to 400 / CodeInvalidArgument.
var ErrBadSelector = errors.New("gearbox: bad selector")

// ErrUnauthorized — the sentinel an Authorize returns to deny an action; may be
// wrapped to attach a reason. Map to 403 / CodePermissionDenied.
var ErrUnauthorized = errors.New("gearbox: not authorized")

// ErrUnauthenticated — no/invalid credentials (returned by the host's auth
// interceptor). Map to 401 / CodeUnauthenticated.
var ErrUnauthenticated = errors.New("gearbox: not authenticated")
