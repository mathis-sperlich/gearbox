package gearbox

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"sync"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

// Execer is the slice of pgx that the CRUD helpers need. *DB, pgx.Tx, and
// *pgxpool.Pool all satisfy it, so the helpers run inside an action body, in a
// caller-owned tx, or straight off the pool (e.g. seeding).
type Execer interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

// DB is the data handle every action body receives: a pgx.Tx with
// Commit/Rollback hidden, so a body can read and write but never end the
// transaction the engine owns. Reach the raw tx with Tx() only for libraries
// that demand one (e.g. a transactional job-queue insert).
type DB struct{ tx pgx.Tx }

// NewDB wraps a tx as a data handle (the engine does this per transition; call
// it yourself only when composing with RunInTx and your own queries).
func NewDB(tx pgx.Tx) *DB { return &DB{tx: tx} }

func (d *DB) Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	return d.tx.Exec(ctx, sql, args...)
}
func (d *DB) Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error) {
	return d.tx.Query(ctx, sql, args...)
}
func (d *DB) QueryRow(ctx context.Context, sql string, args ...any) pgx.Row {
	return d.tx.QueryRow(ctx, sql, args...)
}

// Tx is the escape hatch for the rare caller that needs the raw transaction.
func (d *DB) Tx() pgx.Tx { return d.tx }

// Predicate is one "column op value" filter. Build with Eq/Ne/Gt/Gte/Lt/Lte/In and
// pass to Get/List/Update/Delete; multiple preds are AND-ed.
type Predicate struct {
	col string
	op  string
	val any
}

func Eq(col string, v any) Predicate  { return Predicate{col, "=", v} }
func Ne(col string, v any) Predicate  { return Predicate{col, "<>", v} }
func Gt(col string, v any) Predicate  { return Predicate{col, ">", v} }
func Gte(col string, v any) Predicate { return Predicate{col, ">=", v} }
func Lt(col string, v any) Predicate  { return Predicate{col, "<", v} }
func Lte(col string, v any) Predicate { return Predicate{col, "<=", v} }

// In matches any element of a slice: `col = any($n)`.
func In(col string, vs any) Predicate { return Predicate{col, opIn, vs} }

const opIn = "= any"

// whereClause renders preds into " where ..." with placeholders numbered from
// startArg, returning the matching args in order.
func whereClause(preds []Predicate, startArg int) (string, []any) {
	if len(preds) == 0 {
		return "", nil
	}
	var b strings.Builder
	args := make([]any, 0, len(preds))
	b.WriteString(" where ")
	for i, p := range preds {
		if i > 0 {
			b.WriteString(" and ")
		}
		n := startArg + i
		if p.op == opIn {
			fmt.Fprintf(&b, "%s = any($%d)", quoteIdent(p.col), n)
		} else {
			fmt.Fprintf(&b, "%s %s $%d", quoteIdent(p.col), p.op, n)
		}
		args = append(args, p.val)
	}
	return b.String(), args
}

// Get returns the single row matching preds, or ErrEntityNotFound. It reads no
// lock; pair with GetForUpdate to lock the row for a read-modify-write.
func Get[T any](ctx context.Context, db Execer, preds ...Predicate) (T, error) {
	return getOne[T](ctx, db, false, preds)
}

// GetForUpdate is Get with FOR UPDATE — the row is locked until the tx ends.
func GetForUpdate[T any](ctx context.Context, db Execer, preds ...Predicate) (T, error) {
	return getOne[T](ctx, db, true, preds)
}

func getOne[T any](ctx context.Context, db Execer, lock bool, preds []Predicate) (T, error) {
	var zero T
	m := metaOf(typeOf[T]())
	where, args := whereClause(preds, 1)
	sql := "select * from " + quoteIdent(m.table) + where + " limit 1"
	if lock {
		sql += " for update"
	}
	rows, err := db.Query(ctx, sql, args...)
	if err != nil {
		return zero, err
	}
	v, err := pgx.CollectOneRow(rows, pgx.RowToStructByName[T])
	if errors.Is(err, pgx.ErrNoRows) {
		return zero, fmt.Errorf("%w: %s", ErrEntityNotFound, m.table)
	}
	return v, err
}

// List returns every row matching preds (no preds = the whole table).
func List[T any](ctx context.Context, db Execer, preds ...Predicate) ([]T, error) {
	m := metaOf(typeOf[T]())
	where, args := whereClause(preds, 1)
	rows, err := db.Query(ctx, "select * from "+quoteIdent(m.table)+where, args...)
	if err != nil {
		return nil, err
	}
	return pgx.CollectRows(rows, pgx.RowToStructByName[T])
}

// Insert writes row and returns it re-read (RETURNING *), so DB-generated values
// (the id default, timestamps) come back populated. A zero-valued "id" is omitted
// so the column default generates it; every other column is inserted as given.
func Insert[T any](ctx context.Context, db Execer, row T) (T, error) {
	var zero T
	m := metaOf(typeOf[T]())
	rv := reflect.ValueOf(row)
	cols := make([]string, 0, len(m.cols))
	ph := make([]string, 0, len(m.cols))
	args := make([]any, 0, len(m.cols))
	for _, c := range m.cols {
		fv := rv.Field(c.idx)
		if c.name == m.pkName && fv.IsZero() {
			continue
		}
		cols = append(cols, quoteIdent(c.name))
		args = append(args, fv.Interface())
		ph = append(ph, "$"+strconv.Itoa(len(args)))
	}
	sql := "insert into " + quoteIdent(m.table) + " (" + strings.Join(cols, ", ") +
		") values (" + strings.Join(ph, ", ") + ") returning *"
	rows, err := db.Query(ctx, sql, args...)
	if err != nil {
		return zero, err
	}
	return pgx.CollectOneRow(rows, pgx.RowToStructByName[T])
}

// Update sets every non-id column of row. With no preds it matches by id; pass
// preds to scope it otherwise. Returns rows affected (0 ⇒ no match / RLS denial).
func Update[T any](ctx context.Context, db Execer, row T, preds ...Predicate) (int64, error) {
	m := metaOf(typeOf[T]())
	rv := reflect.ValueOf(row)
	sets := make([]string, 0, len(m.cols))
	args := make([]any, 0, len(m.cols))
	for _, c := range m.cols {
		if c.name == m.pkName {
			continue
		}
		args = append(args, rv.Field(c.idx).Interface())
		sets = append(sets, quoteIdent(c.name)+" = $"+strconv.Itoa(len(args)))
	}
	if len(preds) == 0 {
		if m.pkIdx < 0 {
			return 0, fmt.Errorf("gearbox: Update %s needs a predicate (no id column)", m.table)
		}
		preds = []Predicate{Eq(m.pkName, rv.Field(m.pkIdx).Interface())}
	}
	where, wargs := whereClause(preds, len(args)+1)
	args = append(args, wargs...)
	tag, err := db.Exec(ctx, "update "+quoteIdent(m.table)+" set "+strings.Join(sets, ", ")+where, args...)
	return tag.RowsAffected(), err
}

// Delete removes every row matching preds. At least one pred is required — it
// refuses to truncate a table by accident. Returns rows affected.
func Delete[T any](ctx context.Context, db Execer, preds ...Predicate) (int64, error) {
	if len(preds) == 0 {
		return 0, fmt.Errorf("gearbox: Delete needs at least one predicate")
	}
	m := metaOf(typeOf[T]())
	where, args := whereClause(preds, 1)
	tag, err := db.Exec(ctx, "delete from "+quoteIdent(m.table)+where, args...)
	return tag.RowsAffected(), err
}

// --- reflection over db tags -------------------------------------------------

type column struct {
	name string
	idx  int
}

type tableMeta struct {
	table  string
	cols   []column
	pkName string
	pkIdx  int
}

var (
	metaCache  sync.Map // reflect.Type -> tableMeta
	tableNames sync.Map // reflect.Type -> string (explicit overrides)
)

// RegisterTable overrides the table name for T. Needed only when the derived
// name (snake_case + naive pluralise of the type name) is wrong — an irregular
// plural, or a name that doesn't match the type. NewWorkflow registers the
// engine entity automatically.
func RegisterTable[T any](name string) { tableNames.Store(typeOf[T](), name) }

func typeOf[T any]() reflect.Type { return reflect.TypeOf((*T)(nil)).Elem() }

func metaOf(rt reflect.Type) tableMeta {
	if m, ok := metaCache.Load(rt); ok {
		return m.(tableMeta)
	}
	if rt.Kind() != reflect.Struct {
		panic("gearbox: CRUD type must be a struct, got " + rt.String())
	}
	m := tableMeta{table: tableNameFor(rt), pkIdx: -1}
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		tag := f.Tag.Get("db")
		if tag == "" || tag == "-" || f.PkgPath != "" { // need an exported, db-tagged field
			continue
		}
		name := tag
		if c := strings.IndexByte(name, ','); c >= 0 {
			name = name[:c]
		}
		m.cols = append(m.cols, column{name: name, idx: i})
		if name == "id" {
			m.pkName, m.pkIdx = name, i
		}
	}
	if len(m.cols) == 0 {
		panic("gearbox: " + rt.String() + " has no db-tagged fields; set sqlc emit_db_tags, or supply Load/Save")
	}
	metaCache.Store(rt, m)
	return m
}

func tableNameFor(rt reflect.Type) string {
	if n, ok := tableNames.Load(rt); ok {
		return n.(string)
	}
	return pluralise(toSnake(rt.Name()))
}

func toSnake(s string) string {
	var b strings.Builder
	for i, r := range s {
		if i > 0 && r >= 'A' && r <= 'Z' {
			b.WriteByte('_')
		}
		if r >= 'A' && r <= 'Z' {
			r += 'a' - 'A'
		}
		b.WriteRune(r)
	}
	return b.String()
}

// pluralise is the naive English rule (good for order→orders, category→
// categories). RegisterTable overrides irregulars.
func pluralise(s string) string {
	switch {
	case s == "":
		return s
	case strings.HasSuffix(s, "s"):
		return s
	case strings.HasSuffix(s, "y"):
		return s[:len(s)-1] + "ies"
	default:
		return s + "s"
	}
}
