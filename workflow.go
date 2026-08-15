package gearbox

import (
	"context"
	"fmt"
	"reflect"
	"sort"
)

// WorkflowConfig declares a state machine for one (entity, status column) pair.
// Only Entity is required for a db-tagged struct keyed by an "id" column —
// Load/Save derive from the CRUD helpers, the status accessors from the
// entity's Status field, and the lock SQL from Entity. The status set and every
// legal transition come from Workflow.Transitions.
//
// S is the consumer's status type (any ~string — a defined type like
// `type Status string` gets compile-time protection against constants from
// another workflow; plain string works too).
type WorkflowConfig[T any, S ~string] struct {
	// Entity is the table name; drives audit attribution, lock SQL, CRUD.
	Entity string
	// WorkflowName disambiguates multiple workflows on one entity. Defaults to "default".
	WorkflowName string
	// StatusColumn is the column this workflow gates. Defaults to "status".
	StatusColumn string
	// StatusField names the entity struct field holding the status. Defaults to "Status".
	StatusField string
	// StatusOf and SetStatus override the reflection-derived accessors, for
	// entities whose workflow status is computed rather than stored in a plain
	// string field (e.g. a synthetic status derived from a bool). Set both or
	// neither; when set, StatusField is ignored.
	StatusOf  func(*T) S
	SetStatus func(*T, S)
	// Initial lists the statuses a freshly-inserted row may enter at. Informational.
	Initial []S
	// LockSQL is the single-row lock run before Load. Defaults to
	// "SELECT 1 FROM <Entity> WHERE id = $1 FOR UPDATE".
	LockSQL string
	// Load returns the entity row. Nil derives Get-by-id from the CRUD helpers.
	// pgx.ErrNoRows becomes ErrEntityNotFound.
	Load func(ctx context.Context, db *DB, id string) (*T, error)
	// Save persists the entity after the engine writes its new status. Nil derives
	// Update-by-id (zero rows affected → ErrSaveBlocked, the RLS-denial signal).
	Save func(ctx context.Context, db *DB, e *T) error
}

// Workflow is the state machine for one (entity, status column) pair. Build with
// NewWorkflow; attach operations with NewAction. Statuses and Initial are plain
// strings here — the typed surface (S) lives on the declaration API.
type Workflow[T any, S ~string] struct {
	Entity       string
	WorkflowName string
	StatusColumn string
	Statuses     []string
	Initial      []string
	LockSQL      string
	Load         func(ctx context.Context, db *DB, id string) (*T, error)
	Save         func(ctx context.Context, db *DB, e *T) error

	statusOf  func(*T) string
	setStatus func(*T, string)
	byName    map[string]registered
	wired     bool // Transitions was called
}

// Transitions is the state machine as an adjacency map: for each status, the
// actions legal from it and where each moves the entity. Declared once per
// workflow via Workflow.Transitions — the map is the single place transitions
// live, readable as a diagram. Keyed by the consumer's status type, so a
// constant from another workflow is a compile error:
//
//	Workflow.Transitions(gearbox.Transitions[Status]{
//		StatusPlaced: {Pay.To(StatusPaid), Cancel.To(StatusCancelled)},
//		StatusPaid:   {Ship.To(StatusShipped), Cancel.To(StatusCancelled)},
//	})
type Transitions[S ~string] map[S][]Edge

// RegistryKey uniquely identifies a workflow (entity name, or "entity/workflow").
func (wf *Workflow[T, S]) RegistryKey() string {
	if wf.WorkflowName == "" || wf.WorkflowName == "default" {
		return wf.Entity
	}
	return wf.Entity + "/" + wf.WorkflowName
}

// NewWorkflow builds a Workflow. Misconfiguration (non-struct entity, missing
// status field, derived Load/Save without db tags or an id column) panics here,
// at boot, not at request time.
func NewWorkflow[T any, S ~string](cfg WorkflowConfig[T, S]) *Workflow[T, S] {
	if cfg.Entity == "" {
		panic("gearbox: WorkflowConfig.Entity is required")
	}
	RegisterTable[T](cfg.Entity) // T → table name for the CRUD helpers
	initial := make([]string, len(cfg.Initial))
	for i, s := range cfg.Initial {
		initial[i] = string(s)
	}
	wf := &Workflow[T, S]{
		Entity:       cfg.Entity,
		WorkflowName: defaultStr(cfg.WorkflowName, "default"),
		StatusColumn: defaultStr(cfg.StatusColumn, "status"),
		Initial:      initial,
		LockSQL:      cfg.LockSQL,
		Load:         cfg.Load,
		Save:         cfg.Save,
		byName:       map[string]registered{},
	}
	if wf.LockSQL == "" {
		wf.LockSQL = `SELECT 1 FROM ` + quoteIdent(cfg.Entity) + ` WHERE id = $1 FOR UPDATE`
	}
	switch {
	case cfg.StatusOf != nil && cfg.SetStatus != nil:
		wf.statusOf = func(e *T) string { return string(cfg.StatusOf(e)) }
		wf.setStatus = func(e *T, s string) { cfg.SetStatus(e, S(s)) }
	case cfg.StatusOf != nil || cfg.SetStatus != nil:
		panic("gearbox: " + cfg.Entity + ": StatusOf and SetStatus must be set together")
	default:
		wf.statusOf, wf.setStatus = statusAccessors[T](cfg.StatusField)
	}
	if cfg.Load == nil || cfg.Save == nil {
		// Fail at boot if the CRUD-derived Load/Save can't work on T.
		m := metaOf(typeOf[T]())
		if m.pkIdx < 0 {
			panic("gearbox: entity " + m.table + ` has no "id" column; supply Load and Save`)
		}
	}
	if wf.Load == nil {
		wf.Load = func(ctx context.Context, db *DB, id string) (*T, error) {
			v, err := Get[T](ctx, db, Eq("id", id))
			if err != nil {
				return nil, err
			}
			return &v, nil
		}
	}
	if wf.Save == nil {
		wf.Save = func(ctx context.Context, db *DB, e *T) error {
			n, err := Update(ctx, db, *e)
			if err != nil {
				return err
			}
			if n == 0 {
				return ErrSaveBlocked
			}
			return nil
		}
	}
	return wf
}

// statusAccessors reflects a string-kind struct field (default "Status") on the
// entity. The field index is resolved once here; the closures do no name lookup.
func statusAccessors[T any](field string) (func(*T) string, func(*T, string)) {
	if field == "" {
		field = "Status"
	}
	rt := reflect.TypeOf((*T)(nil)).Elem()
	if rt.Kind() != reflect.Struct {
		panic(fmt.Sprintf("gearbox: entity %s is not a struct", rt))
	}
	f, ok := rt.FieldByName(field)
	if !ok || f.Type.Kind() != reflect.String || f.PkgPath != "" {
		panic(fmt.Sprintf("gearbox: entity %s needs an exported string field %q (or set StatusField)", rt, field))
	}
	idx := f.Index
	get := func(e *T) string { return reflect.ValueOf(e).Elem().FieldByIndex(idx).String() }
	set := func(e *T, s string) { reflect.ValueOf(e).Elem().FieldByIndex(idx).SetString(s) }
	return get, set
}

// Actions returns the descriptors of every registered action, unordered.
func (wf *Workflow[T, S]) Actions() []ActionDescriptor {
	out := make([]ActionDescriptor, 0, len(wf.byName))
	for _, a := range wf.byName {
		out = append(out, a.Descriptor())
	}
	return out
}

// Transitions wires the state machine: for each status, which actions are
// legal and where they move the entity. Call exactly once, after every action
// is registered (a package init block is the natural place). The status set is
// derived from the map — every key and every edge target. Panics at boot on
// misuse: called twice, an empty map, a foreign action, or two edges for the
// same action under one status.
func (wf *Workflow[T, S]) Transitions(t Transitions[S]) {
	if wf.wired {
		panic("gearbox: " + wf.RegistryKey() + ": Transitions already defined")
	}
	if len(t) == 0 {
		panic("gearbox: " + wf.RegistryKey() + ": Transitions map is empty")
	}
	set := map[string]bool{}
	for from, edges := range t {
		set[string(from)] = true
		for _, e := range edges {
			d := e.a.Descriptor()
			if wf.byName[d.Name] != e.a {
				panic(fmt.Sprintf("gearbox: %s: edge under %q references action %s.%s from another workflow",
					wf.RegistryKey(), string(from), d.Workflow, d.Name))
			}
			e.a.addEdge(string(from), actionEdge{target: e.target, deletes: e.deletes})
			if e.target != "" {
				set[e.target] = true
			}
		}
	}
	wf.Statuses = make([]string, 0, len(set))
	for s := range set {
		wf.Statuses = append(wf.Statuses, s)
	}
	sort.Strings(wf.Statuses)
	wf.wired = true
}

// Validate cross-checks the wiring: Transitions was called, every Initial
// entry is a known status, and every registered action appears in the map.
// Call (or MustValidate) from init, after Transitions.
func (wf *Workflow[T, S]) Validate() error {
	if !wf.wired {
		return fmt.Errorf("%s: no Transitions defined — call Workflow.Transitions before Validate", wf.RegistryKey())
	}
	set := map[string]bool{}
	for _, s := range wf.Statuses {
		set[s] = true
	}
	for _, s := range wf.Initial {
		if !set[s] {
			return fmt.Errorf("%s: Initial entry %q not in the transition map", wf.RegistryKey(), s)
		}
	}
	for _, a := range wf.byName {
		if d := a.Descriptor(); len(d.Edges) == 0 {
			return fmt.Errorf("%s.%s: unreachable — the action appears nowhere in the Transitions map",
				wf.RegistryKey(), d.Name)
		}
	}
	return nil
}

// MustValidate panics if Validate fails. Convenience for package init blocks.
func (wf *Workflow[T, S]) MustValidate() {
	if err := wf.Validate(); err != nil {
		panic(err)
	}
}

func defaultStr(v, def string) string {
	if v == "" {
		return def
	}
	return v
}
