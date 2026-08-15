package gearbox

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"
)

// Run is the user-facing entry point: authorize, open a tx via the Engine's
// TxRunner, then lock → load → from-status check → body → status write → save →
// commit. A body error rolls back with no state change.
func Run[T any, S ~string, Req any, Resp any](
	ctx context.Context,
	eng *Engine,
	p Principal,
	action *Action[T, S, Req, Resp],
	id string,
	req Req,
) (Resp, error) {
	var resp Resp
	if err := eng.Authorize(ctx, p, action, []string{id}); err != nil {
		return resp, err
	}
	err := eng.tx.WithTx(ctx, p, func(tx pgx.Tx) error {
		r, err := RunInTx(ctx, tx, eng, action, id, req)
		resp = r
		return err
	})
	return resp, err
}

// Selector selects the target entities for RunAll: one (id) or a batch (ids).
// Declare it once in your proto and embed it in every bulk-capable request —
// the generated message satisfies this interface, no gearbox import:
//
//	message Selector {
//	  option (buf.validate.message).oneof = { fields: ["id", "ids"], required: true };
//	  string id = 1;
//	  repeated string ids = 2;
//	}
type Selector interface {
	GetId() string
	GetIds() []string
}

// IDs adapts a plain id slice to Selector, for callers whose ids don't come
// from a Selector-shaped message: RunAll(ctx, eng, p, action, gearbox.IDs(ids), req).
type IDs []string

// GetId implements Selector; a batch never selects by single id.
func (IDs) GetId() string { return "" }

// GetIds implements Selector.
func (ids IDs) GetIds() []string { return ids }

// selectorIDs normalizes a Selector into the sorted, deduplicated id batch:
// nil, empty, or both-id-and-ids selectors hard-fail with ErrBadSelector.
func selectorIDs(sel Selector) ([]string, error) {
	if sel == nil {
		return nil, fmt.Errorf("%w: nil selector", ErrBadSelector)
	}
	if sel.GetId() != "" && len(sel.GetIds()) > 0 {
		return nil, fmt.Errorf("%w: both id and ids set — set exactly one", ErrBadSelector)
	}
	ids := slices.Clone(sel.GetIds())
	if len(ids) == 0 && sel.GetId() != "" {
		ids = []string{sel.GetId()}
	}
	if len(ids) == 0 {
		return nil, fmt.Errorf("%w: selects no entity (set id or ids)", ErrBadSelector)
	}
	slices.Sort(ids)
	return slices.Compact(ids), nil
}

// RunAll runs one action over every entity sel selects, in a single
// all-or-nothing transaction: authorize once, sort ids (consistent lock order
// across overlapping batches), then lock → check → body → save per entity. Any
// failure rolls the whole batch back. A single-id selector is a batch of one.
// Typically sel is a field of req: RunAll(ctx, eng, p, action, req.GetSelector(), req).
func RunAll[T any, S ~string, Req any, Resp any](
	ctx context.Context,
	eng *Engine,
	p Principal,
	action *Action[T, S, Req, Resp],
	sel Selector,
	req Req,
) ([]Resp, error) {
	ids, err := selectorIDs(sel)
	if err != nil {
		return nil, err
	}
	if err := eng.Authorize(ctx, p, action, ids); err != nil {
		return nil, err
	}
	var out []Resp
	err = eng.Tx(ctx, p, func(tx pgx.Tx) error {
		r, err := RunAllInTx(ctx, tx, eng, action, sel, req)
		out = r
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// RunAllInTx is RunAll inside a transaction the caller owns: same sorted,
// deduplicated, all-or-nothing batch, minus the authorization gate (gate with
// eng.Authorize yourself, or you're a trusted system caller). The batch pays
// two fixed statements — one source write, one multi-row FOR UPDATE in sorted
// id order — instead of two per entity.
func RunAllInTx[T any, S ~string, Req any, Resp any](
	ctx context.Context,
	tx pgx.Tx,
	eng *Engine,
	action *Action[T, S, Req, Resp],
	sel Selector,
	req Req,
) ([]Resp, error) {
	ids, err := selectorIDs(sel)
	if err != nil {
		return nil, err
	}
	wf := action.wf
	// Source attribution — identical for every entity in the batch, set once.
	if err := eng.writeSource(ctx, tx, wf.Entity, action.name); err != nil {
		return nil, err
	}
	// One FOR UPDATE over the whole batch, ordered so overlapping batches lock
	// in a consistent order. An IN list of individual placeholders keeps the
	// comparison typed by the id column (uuid, text, …) and index-friendly.
	if _, err := tx.Exec(ctx, batchLockSQL(wf.Entity, len(ids)), anySlice(ids)...); err != nil {
		return nil, fmt.Errorf("gearbox: lock %s batch: %w", wf.Entity, err)
	}
	out := make([]Resp, 0, len(ids))
	for _, id := range ids {
		r, err := runInTx(ctx, tx, eng, action, id, req, true)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}

// batchLockSQL builds the batch FOR UPDATE for n ids.
func batchLockSQL(entity string, n int) string {
	var b strings.Builder
	b.WriteString("select 1 from ")
	b.WriteString(quoteIdent(entity))
	b.WriteString(" where id in (")
	for i := 1; i <= n; i++ {
		if i > 1 {
			b.WriteByte(',')
		}
		b.WriteByte('$')
		b.WriteString(strconv.Itoa(i))
	}
	b.WriteString(") order by id for update")
	return b.String()
}

func anySlice(ids []string) []any {
	out := make([]any, len(ids))
	for i, id := range ids {
		out[i] = id
	}
	return out
}

// RunInTx runs one action inside a transaction the caller owns — the
// composition primitive. Skips authorization (gate with eng.Authorize yourself,
// or you're a trusted system caller). Compose freely: loop it for a bulk batch,
// mix actions of different workflows in one tx — sort ids first so overlapping
// batches lock in a consistent order.
func RunInTx[T any, S ~string, Req any, Resp any](
	ctx context.Context,
	tx pgx.Tx,
	eng *Engine,
	action *Action[T, S, Req, Resp],
	id string,
	req Req,
) (Resp, error) {
	return runInTx(ctx, tx, eng, action, id, req, false)
}

// runInTx is the per-entity cycle. batched skips source attribution and the
// row lock — RunAllInTx has already done both for the whole batch.
func runInTx[T any, S ~string, Req any, Resp any](
	ctx context.Context,
	tx pgx.Tx,
	eng *Engine,
	action *Action[T, S, Req, Resp],
	id string,
	req Req,
	batched bool,
) (Resp, error) {
	var resp Resp
	wf := action.wf
	db := NewDB(tx)

	if !batched {
		// 0. Source attribution.
		if err := eng.writeSource(ctx, tx, wf.Entity, action.name); err != nil {
			return resp, err
		}
		// 1. FOR UPDATE on the entity row.
		if _, err := tx.Exec(ctx, wf.LockSQL, id); err != nil {
			return resp, fmt.Errorf("gearbox: lock %s: %w", wf.Entity, err)
		}
	}
	// 2. Load.
	entity, err := wf.Load(ctx, db, id)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) || errors.Is(err, ErrEntityNotFound) {
			return resp, fmt.Errorf("%w: %s id=%s", ErrEntityNotFound, wf.Entity, id)
		}
		return resp, fmt.Errorf("gearbox: load %s: %w", wf.Entity, err)
	}
	// 3. Validate: the current status must have an edge for this action.
	got := wf.statusOf(entity)
	edge, ok := action.edges[got]
	if !ok {
		return resp, fmt.Errorf("%w: %s.%s requires from=%v, entity is %s",
			ErrInvalidTransition, wf.RegistryKey(), action.name, action.fromSet(), got)
	}
	// 4. Run the body. nil err = success + transition; non-nil = rollback.
	r, runErr := action.fn(ctx, db, entity, req)
	if runErr != nil {
		return resp, runErr
	}
	resp = r
	// A Deletes edge means the body removed the row — nothing to write or save.
	if edge.deletes {
		return resp, nil
	}
	// 5. Transition along the edge. A Stay edge (empty target) keeps the status.
	if edge.target != "" {
		wf.setStatus(entity, edge.target)
	}
	// 6. Save.
	if err := wf.Save(ctx, db, entity); err != nil {
		return resp, fmt.Errorf("gearbox: save %s: %w", wf.Entity, err)
	}
	return resp, nil
}

// writeSource hands the transition's provenance to the SourceWriter, if any.
func (e *Engine) writeSource(ctx context.Context, tx pgx.Tx, entity, action string) error {
	if e.source == nil {
		return nil
	}
	return e.source.WriteSource(ctx, tx, Source{
		Kind:      "workflow",
		Workflow:  entity,
		Action:    action,
		RequestID: e.reqID(ctx),
	})
}

// quoteIdent double-quotes a Postgres identifier (defence in depth; identifiers
// here are static Go source strings, never user input).
func quoteIdent(name string) string {
	out := make([]byte, 0, len(name)+2)
	out = append(out, '"')
	for i := 0; i < len(name); i++ {
		if name[i] == '"' {
			out = append(out, '"')
		}
		out = append(out, name[i])
	}
	out = append(out, '"')
	return string(out)
}
