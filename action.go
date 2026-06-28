package gearbox

import (
	"context"
	"fmt"
	"sort"
)

// Noop is an action body for transitions whose only effect is the status move
// itself; the engine owns lock → validation → status write → audit.
func Noop[T any, Req any](context.Context, *DB, *T, Req) (struct{}, error) {
	return struct{}{}, nil
}

// ActionConfig is the declarative half of an action — everything but the body
// and the transitions (those live on the workflow's Transitions map).
type ActionConfig struct {
	// Name identifies the action within its workflow; must be unique there.
	Name string
	// Role is handed verbatim to Authorize and surfaced on the Graph. Opaque to
	// the engine — role, scope, capability, whatever your Authorize means by it.
	Role string
}

// ActionFn is the typed business operation: it receives the transaction-scoped
// data handle, the locked entity, and the request payload. A nil error commits
// and transitions; a non-nil error rolls everything back.
type ActionFn[T any, Req any, Resp any] func(
	ctx context.Context, db *DB, entity *T, req Req,
) (Resp, error)

// Action is a typed business operation bound to its workflow. Where it is legal
// from and where it moves the entity come from Workflow.Transitions.
type Action[T any, S ~string, Req any, Resp any] struct {
	wf    *Workflow[T, S]
	name  string
	role  string
	fn    ActionFn[T, Req, Resp]
	edges map[string]string // from status → target status ("" = stay)
}

// NewAction builds an Action and registers it on wf (duplicate names panic at
// init). T is inferred from wf, Req/Resp from the body — call sites annotate
// nothing:
//
//	var Pay = gearbox.NewAction(Workflow, gearbox.ActionConfig{Name: "Pay", Role: "clerk"},
//		func(ctx context.Context, db *gearbox.DB, o *Order, req *pb.PayRequest) (*pb.PayResponse, error) {
//			...
//		})
//
// Wire its transitions on the workflow:
//
//	Workflow.Transitions(gearbox.Transitions[Status]{
//		StatusPlaced: {Pay.To(StatusPaid)},
//	})
func NewAction[T any, S ~string, Req any, Resp any](
	wf *Workflow[T, S], cfg ActionConfig, fn ActionFn[T, Req, Resp],
) *Action[T, S, Req, Resp] {
	a := &Action[T, S, Req, Resp]{
		wf:    wf,
		name:  cfg.Name,
		role:  cfg.Role,
		fn:    fn,
		edges: map[string]string{},
	}
	if _, dupe := wf.byName[a.name]; dupe {
		panic("gearbox: duplicate action name " + a.name + " on " + wf.RegistryKey())
	}
	wf.byName[a.name] = a
	return a
}

// Name returns the action's registered name.
func (a *Action[T, S, Req, Resp]) Name() string { return a.name }

// Edge is one entry of a Transitions map: an action plus the status it moves
// the entity to. Non-generic so actions with different Req/Resp types share a
// map. Build with Action.To or Action.Stay.
type Edge struct {
	a      registered
	target string
}

// To declares that, from the status this edge is filed under, the action moves
// the entity to target. Typed by the workflow's status type — a constant from
// another workflow is a compile error.
func (a *Action[T, S, Req, Resp]) To(target S) Edge { return Edge{a: a, target: string(target)} }

// Stay declares the action is legal from the status this edge is filed under
// but never changes it (logging, annotating, side effects).
func (a *Action[T, S, Req, Resp]) Stay() Edge { return Edge{a: a} }

// addEdge records from → target; duplicate froms for one action panic at boot.
func (a *Action[T, S, Req, Resp]) addEdge(from, target string) {
	if _, dupe := a.edges[from]; dupe {
		panic(fmt.Sprintf("gearbox: %s.%s: duplicate edge from %q", a.wf.RegistryKey(), a.name, from))
	}
	a.edges[from] = target
}

// fromSet returns the statuses this action is legal from, sorted.
func (a *Action[T, S, Req, Resp]) fromSet() []string {
	out := make([]string, 0, len(a.edges))
	for f := range a.edges {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// ActionDescriptor is the type-erased shape used for the Graph and Authorize.
type ActionDescriptor struct {
	Workflow string `json:"workflow"`
	Name     string `json:"name"`
	// Edges maps each legal source status to the target status; an empty target
	// means the action does not change status.
	Edges        map[string]string `json:"edges"`
	Role         string            `json:"role"`
	RequestType  string            `json:"request_type"`
	ResponseType string            `json:"response_type"`
}

// registered is the interface every typed Action satisfies for the registry.
type registered interface {
	Descriptor() ActionDescriptor
	addEdge(from, target string)
}

// Descriptor returns the type-erased shape. Edges is a defensive copy.
func (a *Action[T, S, Req, Resp]) Descriptor() ActionDescriptor {
	var zReq Req
	var zResp Resp
	edges := make(map[string]string, len(a.edges))
	for f, t := range a.edges {
		edges[f] = t
	}
	return ActionDescriptor{
		Workflow:     a.wf.RegistryKey(),
		Name:         a.name,
		Edges:        edges,
		Role:         a.role,
		RequestType:  fmt.Sprintf("%T", zReq),
		ResponseType: fmt.Sprintf("%T", zResp),
	}
}
