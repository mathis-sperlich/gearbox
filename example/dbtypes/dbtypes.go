// Package dbtypes holds hand-declared types wired into the sqlc-generated
// structs via column overrides in sqlc.yaml (sqlc cannot reference a type
// declared in its own output package).
package dbtypes

// OrderStatus is the typed status of an order. The generated Order struct, the
// workflow declaration, and the transitions map all share it, so a status
// constant from another workflow is a compile error.
type OrderStatus string
