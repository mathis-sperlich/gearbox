package authjwt

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"

	"github.com/jackc/pgx/v5"

	"github.com/mathis-sperlich/gearbox"
)

// ClaimsSetting is the transaction-local Postgres setting BindClaims writes
// the caller's claims to, as a JSON object. RLS policies read it back with
// current_setting('request.jwt.claims', true)::jsonb.
const ClaimsSetting = "request.jwt.claims"

// MaxExtraSettings bounds how many settings an ExtraSettings hook may return,
// so the statement BindClaims builds stays small.
const MaxExtraSettings = 8

// ExtraSettings returns transaction-local settings (name → value) to bind next
// to ClaimsSetting, e.g. {"role": "authenticated"} to SET LOCAL ROLE, or an
// active tenant taken from ctx. Identity comes from c only.
type ExtraSettings func(ctx context.Context, c *Claims) (map[string]string, error)

// BindClaims wraps a TxRunner so every transaction it opens first binds the
// caller's claims under ClaimsSetting, plus whatever extra returns (nil means
// none), in one round trip, then runs fn. Names and values travel as
// parameters, never spliced into SQL. It fails closed: a principal that is not
// a non-nil *Claims gets gearbox.ErrUnauthenticated and fn never runs.
//
// Run system work that has no caller on the inner runner directly.
func BindClaims(inner gearbox.TxRunner, extra ExtraSettings) gearbox.TxRunner {
	return gearbox.TxRunnerFunc(func(ctx context.Context, p gearbox.Principal, fn func(pgx.Tx) error) error {
		c, ok := p.(*Claims)
		if !ok || c == nil {
			return fmt.Errorf("%w: transaction needs *authjwt.Claims, got %T", gearbox.ErrUnauthenticated, p)
		}
		sql, args, err := settingsStatement(ctx, c, extra)
		if err != nil {
			return err
		}
		return inner.WithTx(ctx, p, func(tx pgx.Tx) error {
			if _, err := tx.Exec(ctx, sql, args...); err != nil {
				return fmt.Errorf("authjwt: bind claims: %w", err)
			}
			return fn(tx)
		})
	})
}

// settingsStatement builds the one SELECT set_config(...) statement that binds
// c's claims and its extra settings, in name order so the SQL text is stable.
func settingsStatement(ctx context.Context, c *Claims, extra ExtraSettings) (string, []any, error) {
	raw := c.Raw
	if raw == nil {
		raw = map[string]any{"sub": c.Subject}
	}
	claimsJSON, err := json.Marshal(raw)
	if err != nil {
		return "", nil, fmt.Errorf("authjwt: marshal claims: %w", err)
	}
	settings := map[string]string{}
	if extra != nil {
		if settings, err = extra(ctx, c); err != nil {
			return "", nil, err
		}
	}
	if len(settings) > MaxExtraSettings {
		return "", nil, fmt.Errorf("authjwt: %d extra settings, at most %d allowed", len(settings), MaxExtraSettings)
	}
	if _, ok := settings[ClaimsSetting]; ok {
		return "", nil, fmt.Errorf("authjwt: extra setting %q is reserved", ClaimsSetting)
	}
	if _, ok := settings[""]; ok {
		return "", nil, errors.New("authjwt: extra setting with an empty name")
	}
	calls := []string{"set_config($1::text, $2::text, true)"}
	args := []any{ClaimsSetting, string(claimsJSON)}
	for _, name := range slices.Sorted(maps.Keys(settings)) {
		n := len(args) + 1
		calls = append(calls, "set_config($"+strconv.Itoa(n)+"::text, $"+strconv.Itoa(n+1)+"::text, true)")
		args = append(args, name, settings[name])
	}
	return "SELECT " + strings.Join(calls, ", "), args, nil
}
