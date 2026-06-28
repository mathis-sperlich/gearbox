package orders

// ============================================================================
// THE WORKFLOW LOGIC LIVES HERE.
//
// A body runs inside the engine's transaction, after the order row is locked
// and the from-status checked, before the new status is written and the tx
// commits. It gets db (a tx that can't commit/rollback), the loaded order, and
// the typed request. Values are built in Go — no SQL now(), no in-SQL
// arithmetic. Return nil to commit + transition; an error rolls it all back.
//
// Patterns: mutate the OWN order, fetch+update a RELATED row (customer balance,
// product stock), insert a NEW row (an event), enqueue follow-up work.
// ============================================================================

import (
	"context"
	"fmt"
	"time"

	"github.com/mathis-sperlich/gearbox"
	shopdb "github.com/mathis-sperlich/gearbox/example/db"
	ordersv1 "github.com/mathis-sperlich/gearbox/example/gen/ordersv1"
)

// Pay: placed → paid (see the Transitions map in orders.go). Charges the customer and records the event.
var Pay = gearbox.NewAction(orderWorkflow, gearbox.ActionConfig{
	Name: "Pay", Role: "clerk",
}, func(ctx context.Context, db *gearbox.DB, o *Order, req *ordersv1.PayRequest) (*ordersv1.PayResponse, error) {
	now := time.Now().UTC()

	// 1. mutate the OWN order — the engine's Save persists these fields.
	o.PaymentRef = req.GetPaymentRef()
	o.PaidAt = &now

	// 2. fetch + update a RELATED row — add the total to the customer's lifetime
	//    spend. GetForUpdate locks the row; the new value is Go-computed.
	cust, err := gearbox.GetForUpdate[shopdb.Customer](ctx, db, gearbox.Eq("id", o.CustomerID))
	if err != nil {
		return nil, err
	}
	cust.LifetimeSpendCents += o.TotalCents
	if _, err := gearbox.Update(ctx, db, cust); err != nil {
		return nil, err
	}

	// 3. insert a NEW row — an append-only event built in Go.
	if _, err := gearbox.Insert(ctx, db, shopdb.OrderEvent{
		OrderID: o.ID, Kind: "paid", Detail: req.GetPaymentRef(), At: now,
	}); err != nil {
		return nil, err
	}
	return &ordersv1.PayResponse{TotalCents: o.TotalCents, Currency: o.Currency}, nil
})

// Ship: paid → shipped. Decrements stock; refuses (and rolls back) if short.
var Ship = gearbox.NewAction(orderWorkflow, gearbox.ActionConfig{
	Name: "Ship", Role: "clerk",
}, func(ctx context.Context, db *gearbox.DB, o *Order, req *ordersv1.ShipRequest) (*ordersv1.ShipResponse, error) {
	now := time.Now().UTC()
	o.TrackingCode = req.GetTrackingCode()
	o.ShippedAt = &now

	prod, err := gearbox.GetForUpdate[shopdb.Product](ctx, db, gearbox.Eq("id", o.ProductID))
	if err != nil {
		return nil, err
	}
	if prod.Stock < o.Quantity { // business rule → returning an error rolls everything back
		return nil, fmt.Errorf("only %d in stock, order needs %d", prod.Stock, o.Quantity)
	}
	prod.Stock -= o.Quantity
	if _, err := gearbox.Update(ctx, db, prod); err != nil {
		return nil, err
	}
	if _, err := gearbox.Insert(ctx, db, shopdb.OrderEvent{
		OrderID: o.ID, Kind: "shipped", Detail: req.GetTrackingCode(), At: now,
	}); err != nil {
		return nil, err
	}
	return &ordersv1.ShipResponse{TrackingCode: o.TrackingCode}, nil
})

// Cancel: placed|paid → cancelled. Branches on the pre-transition status to
// refund only orders that were actually paid.
var Cancel = gearbox.NewAction(orderWorkflow, gearbox.ActionConfig{
	Name: "Cancel", Role: "clerk",
}, func(ctx context.Context, db *gearbox.DB, o *Order, req *ordersv1.CancelRequest) (*ordersv1.CancelResponse, error) {
	now := time.Now().UTC()
	o.CancelReason = req.GetReason()

	var refunded int64
	if o.Status == StatusPaid { // o.Status is still the pre-transition status
		cust, err := gearbox.GetForUpdate[shopdb.Customer](ctx, db, gearbox.Eq("id", o.CustomerID))
		if err != nil {
			return nil, err
		}
		cust.LifetimeSpendCents -= o.TotalCents
		if _, err := gearbox.Update(ctx, db, cust); err != nil {
			return nil, err
		}
		refunded = o.TotalCents
	}
	if _, err := gearbox.Insert(ctx, db, shopdb.OrderEvent{
		OrderID: o.ID, Kind: "cancelled", Detail: req.GetReason(), At: now,
	}); err != nil {
		return nil, err
	}
	return &ordersv1.CancelResponse{RefundedCents: refunded}, nil
})
