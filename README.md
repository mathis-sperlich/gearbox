# gearbox

A status-driven workflow engine for Postgres. Gearbox lets you declare actions
and a transition map, then runs each action in **one transaction**: it `SELECT`
locks the entity row `FOR UPDATE`, checks whether the current status of the
entity allows the action as per the workflow definition, runs your body, writes
the target status, saves, and commits. Any error — yours or the engine's —
rolls all of it back, including everything your body wrote to other tables, so
state never lands halfway. Only dependency: [pgx](https://github.com/jackc/pgx).

```
go get github.com/mathis-sperlich/gearbox
```

## Use

```go
type Status string

const (Placed, Paid Status = "placed", "paid")

var orderWorkflow = gearbox.NewWorkflow(gearbox.WorkflowConfig[Order, Status]{Entity: "orders"})

var Pay = gearbox.NewAction(orderWorkflow, gearbox.ActionConfig{Name: "Pay"},
	func(ctx context.Context, db *gearbox.DB, o *Order, r Req) (Resp, error) {
		o.PaidAt = time.Now() // just mutate — the engine saves
		return Resp{}, nil
	})

func init() { orderWorkflow.Transitions(gearbox.Transitions[Status]{Placed: {Pay.To(Paid)}}) }
```

`Order` is any struct with `db:"..."` tags (e.g. a sqlc row). The transition
map is the state machine — statuses derive from it, and `MustValidate()`
panics at boot on wiring mistakes. Then wire an engine once and run:

```go
eng := gearbox.NewEngine(gearbox.Config{Tx: gearbox.PoolTx(pool)})

resp, err := gearbox.Run(ctx, eng, principal, Pay, id, req)              // one entity
resps, err := gearbox.RunAll(ctx, eng, principal, Pay, selector, req)    // batch, all-or-nothing
resp, err := gearbox.RunInTx(ctx, tx, eng, Pay, id, req)                 // compose in your own tx
resps, err = gearbox.RunAllInTx(ctx, tx, eng, Pay, gearbox.IDs(ids), req) // batch in your own tx
```

A batch selector can be a proto message with `id`/`ids` fields (see the
example) or a plain slice via `gearbox.IDs`.

**Audit is on by default**: every run writes `{kind, workflow, action,
request_id}` into a transaction-local GUC (`gearbox.source`) before touching
any row, so database triggers can attribute every change in the transaction —
across all tables it touches — to the business action that made it. The
[audit](audit/) subpackage emits the matching idempotent DDL (changes table,
trigger function, one trigger per registered entity). Opt out with
`Config{NoSource: true}`.

Inside a body, `Get` / `GetForUpdate` / `Insert` / `Update` read and write
related rows in the same transaction; richer queries drop to your own SQL
layer (sqlc, raw pgx) on `db.Tx()`. Auth is one
lambda the consumer defines — or omits if not wanted (`Config.Authz`).
Transport is defined by the consumer, but gearbox was built to work with
Connect-RPC and buf.validate: the [example](example/) is a complete
Connect-RPC service with buf validate, JWT auth, typed statuses via a sqlc
override, and an endpoint that runs actions in bulk on multiple entities.

**v0.x** — early, API may change. MIT — see [LICENSE](./LICENSE).
