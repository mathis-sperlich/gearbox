package gearbox

import (
	"context"
	"reflect"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type capRow struct {
	ID   string `db:"id"`
	Name string `db:"name"`
	N    int    `db:"n"`
}

// capExec records the last Exec; Query/QueryRow are unused by Update.
type capExec struct {
	sql  string
	args []any
}

func (c *capExec) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	c.sql, c.args = sql, args
	return pgconn.NewCommandTag("UPDATE 1"), nil
}
func (c *capExec) Query(context.Context, string, ...any) (pgx.Rows, error) { return nil, nil }
func (c *capExec) QueryRow(context.Context, string, ...any) pgx.Row        { return nil }

func TestToSnakeAndPluralise(t *testing.T) {
	for in, want := range map[string]string{"Order": "order", "OrderEvent": "order_event", "Category": "category"} {
		if got := toSnake(in); got != want {
			t.Errorf("toSnake(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"order": "orders", "category": "categories", "orders": "orders", "order_event": "order_events"} {
		if got := pluralise(in); got != want {
			t.Errorf("pluralise(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestMetaOf(t *testing.T) {
	m := metaOf(reflect.TypeOf(capRow{}))
	if m.table != "cap_rows" {
		t.Errorf("table = %q, want cap_rows", m.table)
	}
	if m.pkName != "id" || m.pkIdx != 0 || len(m.cols) != 3 {
		t.Errorf("pk=%q idx=%d cols=%d", m.pkName, m.pkIdx, len(m.cols))
	}
}

func TestWhereClause(t *testing.T) {
	w, args := whereClause([]Predicate{Eq("a", 1), Eq("b", 2)}, 1)
	want := ` where "a" = $1 and "b" = $2`
	if w != want {
		t.Errorf("where = %q, want %q", w, want)
	}
	if len(args) != 2 || args[0] != 1 || args[1] != 2 {
		t.Errorf("args = %v", args)
	}
}

// Update must SET every non-id column, number the WHERE placeholder after the
// SET args, and default the WHERE to the row's id.
func TestUpdateSQL(t *testing.T) {
	c := &capExec{}
	n, err := Update(context.Background(), c, capRow{ID: "x", Name: "ada", N: 7})
	if err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	want := `update "cap_rows" set "name" = $1, "n" = $2 where "id" = $3`
	if c.sql != want {
		t.Fatalf("sql = %q, want %q", c.sql, want)
	}
	if len(c.args) != 3 || c.args[0] != "ada" || c.args[1] != 7 || c.args[2] != "x" {
		t.Fatalf("args = %v", c.args)
	}
}
