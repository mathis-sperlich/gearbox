package gearbox_test

// Shared test harness. The engine is DB-free testable: the only database calls
// it makes directly are tx.Exec (row lock + optional source attribution), and
// fixture workflows provide Load/Save as closures over in-memory state.

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/mathis-sperlich/gearbox"
)

const (
	fxDraft     = "draft"
	fxReady     = "ready"
	fxFailed    = "failed"
	fxCompleted = "completed"
)

type fixtureEntity struct {
	ID     string
	Status string
	Saved  bool
}

// singleFixture builds a workflow whose Load ignores the id and returns ent
// (or pgx.ErrNoRows when ent is nil). Save marks the entity Saved.
func singleFixture(ent *fixtureEntity) *gearbox.Workflow[fixtureEntity, string] {
	return gearbox.NewWorkflow(gearbox.WorkflowConfig[fixtureEntity, string]{
		Entity: "fixtures",
		Load: func(_ context.Context, _ *gearbox.DB, _ string) (*fixtureEntity, error) {
			if ent == nil {
				return nil, pgx.ErrNoRows
			}
			return ent, nil
		},
		Save: func(_ context.Context, _ *gearbox.DB, e *fixtureEntity) error {
			e.Saved = true
			return nil
		},
	})
}

// nilTx is a pgx.Tx whose Exec is a no-op; all other methods panic if called.
type nilTx struct{ pgx.Tx }

func (nilTx) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, nil
}

// execCall records one tx.Exec invocation.
type execCall struct {
	SQL  string
	Args []any
}

// recordingTx records every Exec call (lock SQL / source attribution asserts).
type recordingTx struct {
	pgx.Tx
	Calls []execCall
}

func newRecordingTx() *recordingTx { return &recordingTx{} }

func (t *recordingTx) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	t.Calls = append(t.Calls, execCall{SQL: sql, Args: args})
	return pgconn.CommandTag{}, nil
}

// fakeTxRunner adapts a fixed pgx.Tx into a TxRunner recording the principal.
type fakeTxRunner struct {
	tx        pgx.Tx
	lastPrinc gearbox.Principal
	called    int
}

func (f *fakeTxRunner) WithTx(_ context.Context, p gearbox.Principal, fn func(pgx.Tx) error) error {
	f.called++
	f.lastPrinc = p
	return fn(f.tx)
}

func txRunner(tx pgx.Tx) *fakeTxRunner { return &fakeTxRunner{tx: tx} }

// engineOver builds an engine whose TxRunner runs fn against r's tx.
func engineOver(r gearbox.TxRunner, cfg gearbox.Config) *gearbox.Engine {
	cfg.Tx = r
	return gearbox.NewEngine(cfg)
}

// allowAllEngine is the common case: nil (allow-all) authz, no source.
func allowAllEngine(tx pgx.Tx) (*gearbox.Engine, *fakeTxRunner) {
	r := txRunner(tx)
	return gearbox.NewEngine(gearbox.Config{Tx: r}), r
}
