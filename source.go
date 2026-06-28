package gearbox

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Source describes the provenance of a transition. The engine builds one per Run
// and hands it to the SourceWriter at the start of the transaction, before any
// row is touched, so a database-side audit trigger can attribute the change.
type Source struct {
	// Kind is always "workflow" for engine-driven changes.
	Kind string `json:"kind"`
	// Workflow is the entity name of the workflow that fired.
	Workflow string `json:"workflow"`
	// Action is the action name.
	Action string `json:"action"`
	// RequestID is the correlation ID pulled from the context, if any.
	RequestID string `json:"request_id,omitempty"`
}

// SourceWriter records transition provenance at the start of a workflow
// transaction. Optional; a nil writer skips attribution. Implementations must
// use only the supplied tx so the write joins the transition's transaction.
type SourceWriter interface {
	WriteSource(ctx context.Context, tx pgx.Tx, src Source) error
}

// RequestIDFunc extracts a correlation ID from the context to stamp
// Source.RequestID. The default returns "".
type RequestIDFunc func(ctx context.Context) string

// GUCSourceWriter writes the Source as JSON into a transaction-local Postgres GUC
// via set_config(name, json, true), readable by an AFTER trigger with
// current_setting(name, true) to attribute each change row.
type GUCSourceWriter struct {
	// GUC is the two-part setting name, e.g. "gearbox.source". Required.
	GUC string
}

// WriteSource implements SourceWriter.
func (w GUCSourceWriter) WriteSource(ctx context.Context, tx pgx.Tx, src Source) error {
	raw, err := json.Marshal(src)
	if err != nil {
		return fmt.Errorf("gearbox: marshal source: %w", err)
	}
	if _, err := tx.Exec(ctx, "select set_config($1, $2, true)", w.GUC, string(raw)); err != nil {
		return fmt.Errorf("gearbox: set_config %s: %w", w.GUC, err)
	}
	return nil
}
