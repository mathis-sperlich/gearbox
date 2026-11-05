package authjwt

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/mathis-sperlich/gearbox"
)

// GUC is one transaction-local Postgres setting (a "grand unified
// configuration" parameter), bound with set_config(name, value, true).
//
// `role` is a GUC too: {Name: "role", Value: "authenticated"} is SET LOCAL
// ROLE authenticated, so a ClaimsToGUCs hook can switch the request role in
// the same round trip that binds the claims.
type GUC struct {
	Name  string
	Value string
}

// ClaimsToGUCs maps a verified caller to the settings a TxRunner binds at the
// start of every transaction it opens for that caller. RLS policies then read
// them back with current_setting(name, true). ctx carries request data the
// hook may add (an active tenant, say); identity comes from c only.
type ClaimsToGUCs func(ctx context.Context, c *Claims) ([]GUC, error)

// RequestJWTClaims is the Supabase/PostgREST mapping: c.Raw as JSON under
// `request.jwt.claims`, which auth.uid() / auth.jwt() read. Compose it in a
// custom hook to add a role or app GUCs.
func RequestJWTClaims(_ context.Context, c *Claims) ([]GUC, error) {
	raw := c.Raw
	if raw == nil {
		raw = map[string]any{"sub": c.Subject}
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return nil, fmt.Errorf("authjwt: marshal claims: %w", err)
	}
	return []GUC{{Name: "request.jwt.claims", Value: string(b)}}, nil
}

// SetGUCs binds gucs transaction-locally on tx in one round trip, in order.
// Names and values travel as parameters, never spliced into SQL. An empty
// slice is a no-op.
func SetGUCs(ctx context.Context, tx pgx.Tx, gucs []GUC) error {
	if len(gucs) == 0 {
		return nil
	}
	var sb strings.Builder
	args := make([]any, 0, 2*len(gucs))
	sb.WriteString("SELECT ")
	for i, g := range gucs {
		if g.Name == "" {
			return fmt.Errorf("authjwt: GUC %d has an empty name", i)
		}
		if i > 0 {
			sb.WriteString(", ")
		}
		n := 2*i + 1
		sb.WriteString("set_config($" + strconv.Itoa(n) + "::text, $" + strconv.Itoa(n+1) + "::text, true)")
		args = append(args, g.Name, g.Value)
	}
	if _, err := tx.Exec(ctx, sb.String(), args...); err != nil {
		return fmt.Errorf("authjwt: bind GUCs: %w", err)
	}
	return nil
}

// BindClaims wraps a TxRunner so every transaction it opens first binds the
// GUCs mapGUCs derives from the principal, then runs fn. It fails closed: a
// principal that is not a non-nil *Claims gets gearbox.ErrUnauthenticated and
// fn never runs. A nil mapGUCs means RequestJWTClaims.
//
// Run system work that has no caller on the inner runner directly.
func BindClaims(inner gearbox.TxRunner, mapGUCs ClaimsToGUCs) gearbox.TxRunner {
	if mapGUCs == nil {
		mapGUCs = RequestJWTClaims
	}
	return gearbox.TxRunnerFunc(func(ctx context.Context, p gearbox.Principal, fn func(pgx.Tx) error) error {
		c, ok := p.(*Claims)
		if !ok || c == nil {
			return fmt.Errorf("%w: transaction needs *authjwt.Claims, got %T", gearbox.ErrUnauthenticated, p)
		}
		gucs, err := mapGUCs(ctx, c)
		if err != nil {
			return err
		}
		return inner.WithTx(ctx, p, func(tx pgx.Tx) error {
			if err := SetGUCs(ctx, tx, gucs); err != nil {
				return err
			}
			return fn(tx)
		})
	})
}
