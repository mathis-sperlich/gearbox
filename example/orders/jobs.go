package orders

import (
	"context"
	"log"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mathis-sperlich/gearbox"
	shopdb "github.com/mathis-sperlich/gearbox/example/db"
	ordersv1 "github.com/mathis-sperlich/gearbox/example/gen/ordersv1"
)

// StartAutoCancel runs a background drain: every interval it scans for orders
// left unpaid too long and cancels them through the same Cancel action, in one
// transaction. No job framework — a ticker plus gearbox's composition
// primitive. The candidate query uses FOR UPDATE SKIP LOCKED, so concurrent
// instances split the work instead of colliding. Stop by cancelling ctx.
func StartAutoCancel(ctx context.Context, pool *pgxpool.Pool, eng *gearbox.Engine, every time.Duration) {
	go func() {
		t := time.NewTicker(every)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				if n, err := autoCancel(ctx, pool, eng); err != nil {
					log.Printf("auto-cancel: %v", err)
				} else if n > 0 {
					log.Printf("auto-cancel: cancelled %d order(s)", n)
				}
			}
		}
	}()
}

func autoCancel(ctx context.Context, pool *pgxpool.Pool, eng *gearbox.Engine) (int, error) {
	cutoff := time.Now().UTC().Add(-7 * 24 * time.Hour)
	req := &ordersv1.CancelRequest{Reason: "unpaid for 7 days"}
	var n int
	err := pgx.BeginFunc(ctx, pool, func(tx pgx.Tx) error {
		// The one sqlc query in the example: SKIP LOCKED has no CRUD equivalent.
		// It returns ids already sorted, so overlapping runs lock consistently.
		ids, err := shopdb.New(tx).ListExpiredPlacedOrders(ctx, cutoff)
		if err != nil {
			return err
		}
		for _, id := range ids {
			if _, err := gearbox.RunInTx(ctx, tx, eng, Cancel, id, req); err != nil {
				return err // rolls back the whole batch
			}
		}
		n = len(ids)
		return nil
	})
	return n, err
}
