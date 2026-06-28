// Package orders is the worked gearbox example: a tiny shop where an order
// moves placed → paid → shipped (or → cancelled). The state machine lives here;
// what each transition does lives in actions.go.
//
// Data model (../sql/schema.sql): customers place orders for a product; orders
// emit append-only order_events. Money is integer cents. Every read and write
// goes through gearbox's generic CRUD helpers over the sqlc-generated structs —
// no hand-written queries bar one FOR UPDATE SKIP LOCKED drain.
package orders

import (
	"github.com/mathis-sperlich/gearbox"
	shopdb "github.com/mathis-sperlich/gearbox/example/db"
	"github.com/mathis-sperlich/gearbox/example/dbtypes"
)

// Status is the order's typed status — the same type the sqlc-generated
// Order.Status field carries (dbtypes.OrderStatus, wired via a sqlc column
// override). Using a defined type instead of string means a constant from
// another workflow — or a raw string — is a compile error anywhere a status
// is expected: the Transitions map, To(...), Initial, and body comparisons.
type Status = dbtypes.OrderStatus

const (
	StatusPlaced    Status = "placed"
	StatusPaid      Status = "paid"
	StatusShipped   Status = "shipped"
	StatusCancelled Status = "cancelled"
)

// Order is the engine entity — the sqlc row, mutated in place by action bodies.
type Order = shopdb.Order

// orderWorkflow declares the state machine. Load/Save derive from the db-tagged
// Order struct, the status accessors from its Status field, the lock SQL from
// Entity — the declaration is domain facts only.
var orderWorkflow = gearbox.NewWorkflow(gearbox.WorkflowConfig[Order, Status]{
	Entity:  "orders",
	Initial: []Status{StatusPlaced},
})

// The state machine, readable as a diagram: per status, which actions are
// legal and where each moves the order. The status set derives from the map.
func init() {
	orderWorkflow.Transitions(gearbox.Transitions[Status]{
		StatusPlaced: {Pay.To(StatusPaid), Cancel.To(StatusCancelled)},
		StatusPaid:   {Ship.To(StatusShipped), Cancel.To(StatusCancelled)},
	})
	orderWorkflow.MustValidate()
}
