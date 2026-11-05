package authjwt_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mathis-sperlich/gearbox"
	"github.com/mathis-sperlich/gearbox/authjwt"
)

// recordingTx records Exec calls; every other pgx.Tx method panics.
type recordingTx struct {
	pgx.Tx
	sql  []string
	args [][]any
}

func (r *recordingTx) Exec(_ context.Context, sql string, args ...any) (pgconn.CommandTag, error) {
	r.sql = append(r.sql, sql)
	r.args = append(r.args, args)
	return pgconn.CommandTag{}, nil
}

// runnerOver is a TxRunner whose every transaction is tx.
func runnerOver(tx pgx.Tx) gearbox.TxRunner {
	return gearbox.TxRunnerFunc(func(_ context.Context, _ gearbox.Principal, fn func(pgx.Tx) error) error {
		return fn(tx)
	})
}

func TestBindClaims_BindsClaimsAndExtrasBeforeBody(t *testing.T) {
	// Given a runner that also binds a role and the user id
	tx := &recordingTx{}
	roleAndUser := func(_ context.Context, c *authjwt.Claims) (map[string]string, error) {
		return map[string]string{"role": "authenticated", "app.user": c.Subject}, nil
	}
	signedIn := &authjwt.Claims{Subject: "u9", Raw: []byte(`{"email":"a@b.c","sub":"u9"}`)}
	// When a transaction runs for a signed-in caller
	err := authjwt.BindClaims(runnerOver(tx), roleAndUser).WithTx(context.Background(), signedIn, func(tx pgx.Tx) error {
		_, err := tx.Exec(context.Background(), "body")
		return err
	})
	// Then one statement binds claims and extras (in name order), before the body
	if err != nil {
		t.Fatalf("WithTx: %v", err)
	}
	if len(tx.sql) != 2 || tx.sql[1] != "body" {
		t.Fatalf("exec order = %q", tx.sql)
	}
	boundArgs := tx.args[0]
	want := []any{authjwt.ClaimsSetting, `{"email":"a@b.c","sub":"u9"}`, "app.user", "u9", "role", "authenticated"}
	if fmt.Sprint(boundArgs) != fmt.Sprint(want) {
		t.Fatalf("args = %v, want %v", boundArgs, want)
	}
}

func TestBindClaims_NoRawBindsSubject(t *testing.T) {
	// Given claims built in code, without a raw claim set
	tx := &recordingTx{}
	builtInCode := &authjwt.Claims{Subject: "u1"}
	// When a transaction runs for them with no extras
	err := authjwt.BindClaims(runnerOver(tx), nil).WithTx(context.Background(), builtInCode, func(pgx.Tx) error { return nil })
	// Then the bound claims hold just the subject
	if err != nil {
		t.Fatalf("WithTx: %v", err)
	}
	var bound map[string]any
	if err := json.Unmarshal([]byte(tx.args[0][1].(string)), &bound); err != nil || bound["sub"] != "u1" || len(bound) != 1 {
		t.Fatalf("bound claims = %v (%v)", tx.args[0][1], err)
	}
}

func TestBindClaims_RejectsNonClaimsPrincipal(t *testing.T) {
	// Given principals that are not a non-nil *authjwt.Claims
	nonClaimsPrincipals := map[string]gearbox.Principal{
		"nil":        nil,
		"nil claims": (*authjwt.Claims)(nil),
		"value":      authjwt.Claims{Subject: "u"},
		"string":     "u",
	}
	for name, nonClaimsPrincipal := range nonClaimsPrincipals {
		t.Run(name, func(t *testing.T) {
			tx := &recordingTx{}
			bodyRan := false
			// When a transaction runs for it
			err := authjwt.BindClaims(runnerOver(tx), nil).WithTx(context.Background(), nonClaimsPrincipal, func(pgx.Tx) error {
				bodyRan = true
				return nil
			})
			// Then it is unauthenticated and nothing touches the database
			if !errors.Is(err, gearbox.ErrUnauthenticated) {
				t.Fatalf("err = %v, want ErrUnauthenticated", err)
			}
			if bodyRan || len(tx.sql) != 0 {
				t.Fatal("transaction body ran for a non-Claims principal")
			}
		})
	}
}

func TestBindClaims_RefusesBadExtras(t *testing.T) {
	// Given extras hooks that fail or return settings BindClaims must refuse
	boom := errors.New("boom")
	tooMany := map[string]string{}
	for i := range authjwt.MaxExtraSettings + 1 {
		tooMany[fmt.Sprintf("app.s%d", i)] = "v"
	}
	badExtras := map[string]authjwt.ExtraSettings{
		"hook error": func(context.Context, *authjwt.Claims) (map[string]string, error) { return nil, boom },
		"too many":   func(context.Context, *authjwt.Claims) (map[string]string, error) { return tooMany, nil },
		"overrides claims": func(context.Context, *authjwt.Claims) (map[string]string, error) {
			return map[string]string{authjwt.ClaimsSetting: "{}"}, nil
		},
		"empty name": func(context.Context, *authjwt.Claims) (map[string]string, error) {
			return map[string]string{"": "x"}, nil
		},
	}
	for name, badExtra := range badExtras {
		t.Run(name, func(t *testing.T) {
			tx := &recordingTx{}
			// When a transaction runs with it
			err := authjwt.BindClaims(runnerOver(tx), badExtra).WithTx(context.Background(), &authjwt.Claims{Subject: "u"}, func(pgx.Tx) error {
				t.Fatal("body ran despite bad extras")
				return nil
			})
			// Then it fails before anything reaches the database
			if err == nil || len(tx.sql) != 0 {
				t.Fatalf("err = %v, execs = %v", err, tx.sql)
			}
		})
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

	// Given a runner binding a tenant whose value needs quoting
	quotedTenant := func(context.Context, *authjwt.Claims) (map[string]string, error) {
		return map[string]string{"app.tenant": "it's-t1"}, nil
	}
	runner := authjwt.BindClaims(gearbox.PoolTx(pool), quotedTenant)
	signedIn := &authjwt.Claims{Subject: "u1", Raw: []byte(`{"email":"a@b.c","sub":"u1"}`)}

	// When a transaction reads the settings back
	var sub, tenant string
	err = runner.WithTx(ctx, signedIn, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx,
			`SELECT current_setting('request.jwt.claims', true)::jsonb->>'sub', current_setting('app.tenant', true)`,
		).Scan(&sub, &tenant)
	})

	// Then it sees them
	if err != nil {
		t.Fatalf("WithTx: %v", err)
	}
	if sub != "u1" || tenant != "it's-t1" {
		t.Fatalf("sub = %q tenant = %q", sub, tenant)
	}
	// And a fresh transaction on the pool sees nothing (transaction-local)
	var after *string
	if err := pool.QueryRow(ctx, `SELECT nullif(current_setting('app.tenant', true), '')`).Scan(&after); err != nil {
		t.Fatalf("read after: %v", err)
	}
	if after != nil {
		t.Fatalf("app.tenant leaked past the transaction: %q", *after)
	}

	// Given a runner binding the role setting, when the authenticated role exists
	var hasRole bool
	if err := pool.QueryRow(ctx, `SELECT exists(SELECT 1 FROM pg_roles WHERE rolname = 'authenticated')`).Scan(&hasRole); err != nil {
		t.Fatalf("pg_roles: %v", err)
	}
	if !hasRole {
		t.Log("no authenticated role; skipping role switch check")
		return
	}
	authenticatedRole := func(context.Context, *authjwt.Claims) (map[string]string, error) {
		return map[string]string{"role": "authenticated"}, nil
	}
	// When a transaction asks who it runs as
	var user string
	if err := authjwt.BindClaims(gearbox.PoolTx(pool), authenticatedRole).WithTx(ctx, signedIn, func(tx pgx.Tx) error {
		return tx.QueryRow(ctx, `SELECT current_user::text`).Scan(&user)
	}); err != nil {
		t.Fatalf("role WithTx: %v", err)
	}
	// Then it runs as the bound role
	if user != "authenticated" {
		t.Fatalf("current_user = %q, want authenticated", user)
	}
}
