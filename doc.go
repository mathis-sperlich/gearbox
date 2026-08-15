// Package gearbox is a status-driven workflow engine for Postgres: declare each
// business operation as a typed action, wire the state machine as a Transitions
// map (per status, which actions are legal and where they move the entity), and
// the engine owns the transaction — lock, load, from-status check, body, status
// write, save. A body error rolls the whole thing back, so there is no "halfway
// through the update" state.
//
//	Workflow[T]           state machine for one entity + status column. NewWorkflow.
//	Action[T, Req, Resp]  one typed operation; self-registers. NewAction.
//	Transitions           the adjacency map: {status: [Action.To(target), ...]}.
//	Run                   authorize + open tx + execute one action.
//	RunAll                one-or-many via a Selector, one all-or-nothing tx.
//	RunInTx               execute inside a caller-owned tx — the composition
//	                      primitive (bulk loops, mixed actions, background jobs).
//
// Bodies receive a *DB (a tx that cannot commit or roll back) and read/write via
// the row helpers (Get/GetForUpdate/Insert/Update, Eq predicates) over db-tagged
// structs, dropping to sqlc or raw pgx via db.Tx() when a query earns it.
//
// Bring your own auth: a TxRunner opens the tx with whatever tenancy the host
// wants (plain pool via PoolTx, or an RLS-bound tx), and Authorize is one func
// implementing whatever access control means to you. Principal is opaque.
// Transport is yours too — call Run from Connect-RPC, net/http, or anywhere;
// the connectgear subpackage maps gearbox errors to Connect codes.
package gearbox
