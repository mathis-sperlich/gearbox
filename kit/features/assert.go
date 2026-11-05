package features

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
)

// Querier is the slice of pgx AssertKnown needs; *pgxpool.Pool, *pgx.Conn and
// pgx.Tx satisfy it.
type Querier interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
}

// DefaultNamesQuery reads the feature names stored in a feature_access table.
const DefaultNamesQuery = `select distinct feature from feature_access`

// AssertKnown red-lights boot when the database stores a feature name the
// compiled enum doesn't know — a typo'd row, or a row left behind by an enum
// value that was deleted — instead of letting it surface later as a silently
// dark feature. query returns one text column of names (DefaultNamesQuery
// when empty).
func (r *Registry[F]) AssertKnown(ctx context.Context, db Querier, query string) error {
	if query == "" {
		query = DefaultNamesQuery
	}
	rows, err := db.Query(ctx, query)
	if err != nil {
		return fmt.Errorf("features: querying stored feature names: %w", err)
	}
	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return fmt.Errorf("features: reading stored feature names: %w", err)
	}
	if unknown := r.Unknown(names); len(unknown) > 0 {
		return fmt.Errorf("features: database stores feature names the enum doesn't know: %v — add the enum value or delete the rows", unknown)
	}
	return nil
}
