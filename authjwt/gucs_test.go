package authjwt_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mathis-sperlich/gearbox"
	"github.com/mathis-sperlich/gearbox/authjwt"
)

// recTx records Exec calls; every other pgx.Tx method panics.
type recTx struct {
	pgx.Tx
	sql  []string
	args [][]any
}

func (r *recTx) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	r.sql = append(r.sql, sql)
	r.args = append(r.args, args)
	return pgconn.CommandTag{}, nil
}

func fakeRunner(tx pgx.Tx) gearbox.TxRunner {
	return gearbox.TxRunnerFunc(func(_ context.Context, _ gearbox.Principal, fn func(pgx.Tx) error) error {
		return fn(tx)
	})
}

func TestRequestJWTClaims_MarshalsRaw(t *testing.T) {
	gucs, err := authjwt.RequestJWTClaims(context.Background(), &authjwt.Claims{
		Subject: "u1",
		Raw:     map[string]any{"sub": "u1", "role": "authenticated"},
	})
	if err != nil {
		t.Fatalf("RequestJWTClaims: %v", err)
	}
	if len(gucs) != 1 || gucs[0].Name != "request.jwt.claims" {
		t.Fatalf("gucs = %v", gucs)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(gucs[0].Value), &got); err != nil || got["sub"] != "u1" || got["role"] != "authenticated" {
		t.Fatalf("value = %s (%v)", gucs[0].Value, err)
	}
}

func TestBindClaims_RejectsNonClaimsPrincipal(t *testing.T) {
	for name, p := range map[string]gearbox.Principal{
		"nil":        nil,
		"nil claims": (*authjwt.Claims)(nil),
		"value":      authjwt.Claims{Subject: "u"},
		"string":     "u",
	} {
		t.Run(name, func(t *testing.T) {
			tx := &recTx{}
			ran := false
			err := authjwt.BindClaims(fakeRunner(tx), nil).WithTx(context.Background(), p, func(pgx.Tx) error {
				ran = true
				return nil
			})
			if !errors.Is(err, gearbox.ErrUnauthenticated) {
				t.Fatalf("err = %v, want ErrUnauthenticated", err)
			}
			if ran || len(tx.sql) != 0 {
				t.Fatal("transaction body ran for a non-Claims principal")
			}
		})
	}
}

func TestBindClaims_SetsGUCsBeforeBody(t *testing.T) {
	tx := &recTx{}
	hook := func(_ context.Context, c *authjwt.Claims) ([]authjwt.GUC, error) {
		return []authjwt.GUC{{Name: "role", Value: "authenticated"}, {Name: "app.user", Value: c.Subject}}, nil
	}
	err := authjwt.BindClaims(fakeRunner(tx), hook).WithTx(context.Background(), &authjwt.Claims{Subject: "u9"}, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), "body")
		return err
	})
	if err != nil {
		t.Fatalf("WithTx: %v", err)
	}
	if len(tx.sql) != 2 || tx.sql[1] != "body" {
		t.Fatalf("exec order = %q", tx.sql)
	}
	want := []any{"role", "authenticated", "app.user", "u9"}
	if len(tx.args[0]) != len(want) {
		t.Fatalf("args = %v", tx.args[0])
	}
	for i := range want {
		if tx.args[0][i] != want[i] {
			t.Fatalf("args = %v, want %v", tx.args[0], want)
		}
	}
}

func TestBindClaims_HookErrorStopsTx(t *testing.T) {
	tx := &recTx{}
	boom := errors.New("boom")
	err := authjwt.BindClaims(fakeRunner(tx), func(context.Context, *authjwt.Claims) ([]authjwt.GUC, error) {
		return nil, boom
	}).WithTx(context.Background(), &authjwt.Claims{Subject: "u"}, func(pgx.Tx) error {
		t.Fatal("body ran after hook error")
		return nil
	})
	if !errors.Is(err, boom) || len(tx.sql) != 0 {
		t.Fatalf("err = %v, execs = %v", err, tx.sql)
	}
}

func TestSetGUCs_EmptyNameRefused(t *testing.T) {
	if err := authjwt.SetGUCs(context.Background(), &recTx{}, []authjwt.GUC{{Value: "x"}}); err == nil {
		t.Fatal("SetGUCs accepted an empty GUC name")
	}
}

// TestBindClaims_Postgres proves the bound settings are visible inside the
// transaction and gone after it. It creates nothing in the database.
func TestBindClaims_Postgres(t *testing.T) {
	url := os.Getenv("GEARBOX_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("GEARBOX_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()

	hook := func(ctx context.Context, c *authjwt.Claims) ([]authjwt.GUC, error) {
		gucs, err := authjwt.RequestJWTClaims(ctx, c)
		return append(gucs, authjwt.GUC{Name: "app.tenant", Value: "it's-t1"}), err
	}
	runner := authjwt.BindClaims(gearbox.PoolTx(pool), hook)
	claims := &authjwt.Claims{Subject: "u1", Raw: map[string]any{"sub": "u1", "email": "a@b.c"}}

	var sub, tenant string
	err = runner.WithTx(ctx, claims, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT current_setting('request.jwt.claims', true)::jsonb->>'sub', current_setting('app.tenant', true)`,
		).Scan(&sub, &tenant)
	})
	if err != nil {
		t.Fatalf("WithTx: %v", err)
	}
	if sub != "u1" || tenant != "it's-t1" {
		t.Fatalf("sub = %q tenant = %q", sub, tenant)
	}

	// Transaction-local: a fresh transaction on the pool sees nothing.
	var after *string
	if err := pool.QueryRow(ctx, `SELECT nullif(current_setting('app.tenant', true), '')`).Scan(&after); err != nil {
		t.Fatalf("read after: %v", err)
	}
	if after != nil {
		t.Fatalf("app.tenant leaked past the transaction: %q", *after)
	}

	// role is a GUC: binding it switches current_user for the transaction.
	var hasRole bool
	if err := pool.QueryRow(ctx, `SELECT exists(SELECT 1 FROM pg_roles WHERE rolname = 'authenticated')`).Scan(&hasRole); err != nil {
		t.Fatalf("pg_roles: %v", err)
	}
	if !hasRole {
		t.Log("no authenticated role; skipping role switch check")
		return
	}
	roleRunner := authjwt.BindClaims(gearbox.PoolTx(pool), func(context.Context, *authjwt.Claims) ([]authjwt.GUC, error) {
		return []authjwt.GUC{{Name: "role", Value: "authenticated"}}, nil
	})
	var user string
	if err := roleRunner.WithTx(ctx, claims, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT current_user::text`).Scan(&user)
	}); err != nil {
		t.Fatalf("role WithTx: %v", err)
	}
	if user != "authenticated" {
		t.Fatalf("current_user = %q, want authenticated", user)
	}
}
