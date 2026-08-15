package gearbox_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/mathis-sperlich/gearbox"
)

// selReq mirrors a client-declared Selector proto message (GetId/GetIds).
type selReq struct {
	id  string
	ids []string
}

func (r selReq) GetId() string    { return r.id }
func (r selReq) GetIds() []string { return r.ids }

// mapFixture: workflow over a map of entities keyed by id.
func mapFixture(m map[string]*fixtureEntity) *gearbox.Workflow[fixtureEntity, string] {
	return gearbox.NewWorkflow(gearbox.WorkflowConfig[fixtureEntity, string]{
		Entity: "fixtures",
		Load: func(_ context.Context, _ *gearbox.DB, id string) (*fixtureEntity, error) {
			e, ok := m[id]
			if !ok {
				return nil, pgx.ErrNoRows
			}
			return e, nil
		},
		Save: func(_ context.Context, _ *gearbox.DB, e *fixtureEntity) error {
			e.Saved = true
			return nil
		},
	})
}

func TestRunAll_BatchTransitionsAllInOneTx(t *testing.T) {
	m := map[string]*fixtureEntity{
		"a": {ID: "a", Status: fxDraft},
		"b": {ID: "b", Status: fxDraft},
	}
	a := publishOn(mapFixture(m))
	eng, runner := allowAllEngine(nilTx{})

	out, err := gearbox.RunAll(context.Background(), eng, nil, a, selReq{ids: []string{"b", "a", "b"}}, struct{}{})
	if err != nil {
		t.Fatalf("RunAll: %v", err)
	}
	if len(out) != 2 { // deduped
		t.Fatalf("len(out) = %d, want 2", len(out))
	}
	if runner.called != 1 {
		t.Fatalf("TxRunner called %d times, want 1 (one tx for the batch)", runner.called)
	}
	if m["a"].Status != fxReady || m["b"].Status != fxReady {
		t.Fatalf("statuses = %q/%q, want ready/ready", m["a"].Status, m["b"].Status)
	}
}

func TestRunAll_SingleIdIsBatchOfOne(t *testing.T) {
	m := map[string]*fixtureEntity{"a": {ID: "a", Status: fxDraft}}
	a := publishOn(mapFixture(m))
	eng, _ := allowAllEngine(nilTx{})

	out, err := gearbox.RunAll(context.Background(), eng, nil, a, selReq{id: "a"}, struct{}{})
	if err != nil || len(out) != 1 {
		t.Fatalf("out=%v err=%v, want 1 result", out, err)
	}
	if m["a"].Status != fxReady {
		t.Fatalf("status = %q, want ready", m["a"].Status)
	}
}

func TestRunAll_OneFailureFailsTheWholeBatch(t *testing.T) {
	m := map[string]*fixtureEntity{
		"a": {ID: "a", Status: fxDraft},
		"b": {ID: "b", Status: fxReady}, // wrong from-status
	}
	a := publishOn(mapFixture(m))
	eng, _ := allowAllEngine(nilTx{})

	_, err := gearbox.RunAll(context.Background(), eng, nil, a, selReq{ids: []string{"a", "b"}}, struct{}{})
	if !errors.Is(err, gearbox.ErrInvalidTransition) {
		t.Fatalf("err = %v, want ErrInvalidTransition", err)
	}
}

func TestRunAll_BadSelectorHardFails(t *testing.T) {
	a := publishOn(mapFixture(nil))
	eng, runner := allowAllEngine(nilTx{})

	for name, sel := range map[string]gearbox.Selector{
		"empty":    selReq{},
		"nil":      nil,
		"both-set": selReq{id: "a", ids: []string{"b"}},
	} {
		if _, err := gearbox.RunAll(context.Background(), eng, nil, a, sel, struct{}{}); !errors.Is(err, gearbox.ErrBadSelector) {
			t.Fatalf("%s selector: err = %v, want ErrBadSelector", name, err)
		}
	}
	if runner.called != 0 {
		t.Fatal("tx opened for a bad selector")
	}
}

func TestRunAllInTx_ComposesOnCallerTxWithoutGate(t *testing.T) {
	m := map[string]*fixtureEntity{
		"a": {ID: "a", Status: fxDraft},
		"b": {ID: "b", Status: fxDraft},
	}
	a := publishOn(mapFixture(m))
	var authzCalls int
	authz := gearbox.Authorize(func(context.Context, gearbox.Principal, gearbox.ActionDescriptor, []string) error {
		authzCalls++
		return nil
	})
	runner := txRunner(nilTx{})
	eng := engineOver(runner, gearbox.Config{Authz: authz})

	out, err := gearbox.RunAllInTx(context.Background(), nilTx{}, eng, a, gearbox.IDs{"b", "a"}, struct{}{})
	if err != nil || len(out) != 2 {
		t.Fatalf("out=%v err=%v, want 2 results", out, err)
	}
	if authzCalls != 0 {
		t.Fatal("RunAllInTx must not consult Authorize")
	}
	if runner.called != 0 {
		t.Fatal("RunAllInTx must not open its own tx")
	}
	if m["a"].Status != fxReady || m["b"].Status != fxReady {
		t.Fatalf("statuses = %q/%q, want ready/ready", m["a"].Status, m["b"].Status)
	}
}

func TestIDs_SelectorAdapter(t *testing.T) {
	m := map[string]*fixtureEntity{"a": {ID: "a", Status: fxDraft}}
	a := publishOn(mapFixture(m))
	eng, _ := allowAllEngine(nilTx{})

	if _, err := gearbox.RunAll(context.Background(), eng, nil, a, gearbox.IDs{"a"}, struct{}{}); err != nil {
		t.Fatalf("RunAll with IDs: %v", err)
	}
	if m["a"].Status != fxReady {
		t.Fatalf("status = %q, want ready", m["a"].Status)
	}
	if _, err := gearbox.RunAll(context.Background(), eng, nil, a, gearbox.IDs{}, struct{}{}); !errors.Is(err, gearbox.ErrBadSelector) {
		t.Fatalf("empty IDs: err = %v, want ErrBadSelector", err)
	}
}

func TestRunAll_AuthorizesOnceWithAllIDs(t *testing.T) {
	m := map[string]*fixtureEntity{
		"a": {ID: "a", Status: fxDraft},
		"b": {ID: "b", Status: fxDraft},
	}
	a := publishOn(mapFixture(m))
	var calls int
	var gotIDs []string
	authz := gearbox.Authorize(func(_ context.Context, _ gearbox.Principal, _ gearbox.ActionDescriptor, ids []string) error {
		calls++
		gotIDs = ids
		return nil
	})
	eng := engineOver(txRunner(nilTx{}), gearbox.Config{Authz: authz})

	if _, err := gearbox.RunAll(context.Background(), eng, nil, a, selReq{ids: []string{"b", "a"}}, struct{}{}); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(gotIDs) != 2 || gotIDs[0] != "a" { // sorted
		t.Fatalf("authz calls=%d ids=%v, want 1 call with sorted [a b]", calls, gotIDs)
	}
}
