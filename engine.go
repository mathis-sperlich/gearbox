package gearbox

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Principal is the opaque caller identity threaded through the engine. gearbox
// never inspects it; it is passed verbatim to the TxRunner (tenancy context) and
// Authorize. System callers use RunInTx and pass none.
type Principal any

// TxRunner opens a transaction for a principal and runs fn inside it, committing
// on nil and rolling back on error. This is the seam where a host binds its
// tenancy model (plain pgx, RLS transaction, tenant GUC) — anything yielding a
// pgx.Tx. gearbox issues only row-lock + status-write SQL inside it.
type TxRunner interface {
	WithTx(ctx context.Context, p Principal, fn func(pgx.Tx) error) error
}

// TxRunnerFunc adapts an ordinary function to a TxRunner.
type TxRunnerFunc func(ctx context.Context, p Principal, fn func(pgx.Tx) error) error

// WithTx implements TxRunner.
func (f TxRunnerFunc) WithTx(ctx context.Context, p Principal, fn func(pgx.Tx) error) error {
	return f(ctx, p, fn)
}

// PoolTx is the default tenancy-free TxRunner: a plain pgx transaction on the
// pool, commit on success / rollback on error. The principal is ignored — write
// your own TxRunner to bind it (e.g. an RLS transaction).
func PoolTx(pool *pgxpool.Pool) TxRunner {
	return TxRunnerFunc(func(ctx context.Context, _ Principal, fn func(pgx.Tx) error) error {
		return pgx.BeginFunc(ctx, pool, fn)
	})
}

// Authorize decides whether principal p may run action over ids. Return nil to
// allow, an error (e.g. ErrUnauthorized) to deny. The whole policy is the
// host's: read roles, scopes, or tenancy off p (or ctx) and decide — gearbox has
// no built-in RBAC. Consulted on Run; RunInTx skips it. Nil allows everything.
type Authorize func(ctx context.Context, p Principal, action ActionDescriptor, ids []string) error

// Engine wires the pluggable pieces. Safe for concurrent use.
type Engine struct {
	tx        TxRunner
	authz     Authorize
	source    SourceWriter
	requestID RequestIDFunc
}

// Config configures an Engine. Tx is required; the rest are optional.
type Config struct {
	// Tx opens transactions with the host's tenancy context. Required.
	Tx TxRunner
	// Authz gates Run. Nil allows everything — set it (or rely on database-layer
	// RLS) before exposing the engine to untrusted callers.
	Authz Authorize
	// Source records transition provenance for an audit log. Audit attribution
	// is ON by default: a nil Source gets GUCSourceWriter{GUC: "gearbox.source"}
	// (one tx-local set_config per run — harmless without triggers; see the
	// audit subpackage for the matching DDL). Set NoSource to opt out.
	Source SourceWriter
	// NoSource disables source attribution entirely (overrides Source).
	NoSource bool
	// RequestID extracts a correlation ID from the context for Source. Optional.
	RequestID RequestIDFunc
}

// DefaultGUC is the transaction-local setting Source attribution writes to
// when no SourceWriter is configured.
const DefaultGUC = "gearbox.source"

// NewEngine builds an Engine. Panics if Tx is nil.
func NewEngine(cfg Config) *Engine {
	if cfg.Tx == nil {
		panic("gearbox: NewEngine requires a non-nil Tx (TxRunner)")
	}
	src := cfg.Source
	if cfg.NoSource {
		src = nil
	} else if src == nil {
		src = GUCSourceWriter{GUC: DefaultGUC}
	}
	return &Engine{
		tx:        cfg.Tx,
		authz:     cfg.Authz,
		source:    src,
		requestID: cfg.RequestID,
	}
}

// Tx opens a transaction through the engine's TxRunner — the entry point for
// composed operations (loop RunInTx for a bulk batch, mix actions in one tx).
func (e *Engine) Tx(ctx context.Context, p Principal, fn func(pgx.Tx) error) error {
	return e.tx.WithTx(ctx, p, fn)
}

// Authorize runs the engine's Authorize func for an action over ids (nil policy
// allows). Run calls it for you; composed RunInTx paths gate themselves with it.
func (e *Engine) Authorize(ctx context.Context, p Principal, a interface{ Descriptor() ActionDescriptor }, ids []string) error {
	if e.authz == nil {
		return nil
	}
	return e.authz(ctx, p, a.Descriptor(), ids)
}

func (e *Engine) reqID(ctx context.Context) string {
	if e.requestID == nil {
		return ""
	}
	return e.requestID(ctx)
}
