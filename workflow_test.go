package gearbox_test

import (
	"strings"
	"testing"

	"github.com/mathis-sperlich/gearbox"
)

func TestWorkflow_ValidateAcceptsConsistentWorkflow(t *testing.T) {
	wf := singleFixture(&fixtureEntity{ID: "e1", Status: fxDraft})
	publishOn(wf)
	if err := wf.Validate(); err != nil {
		t.Fatalf("Validate of consistent workflow: %v", err)
	}
}

func TestWorkflow_ValidateWithoutTransitionsErrors(t *testing.T) {
	wf := singleFixture(nil)
	err := wf.Validate()
	if err == nil || !strings.Contains(err.Error(), "no Transitions") {
		t.Fatalf("error = %v, want a no-Transitions error", err)
	}
}

func TestWorkflow_ValidateRejectsActionMissingFromTheMap(t *testing.T) {
	wf := singleFixture(nil)
	wired := gearbox.NewAction(wf, gearbox.ActionConfig{Name: "Wired"}, gearbox.Noop[fixtureEntity, struct{}])
	gearbox.NewAction(wf, gearbox.ActionConfig{Name: "Orphan"}, gearbox.Noop[fixtureEntity, struct{}])
	wf.Transitions(gearbox.Transitions[string]{fxDraft: {wired.To(fxReady)}})
	err := wf.Validate()
	if err == nil || !strings.Contains(err.Error(), "unreachable") {
		t.Fatalf("error = %v, want an unreachable-action error", err)
	}
}

func TestWorkflow_ValidateRejectsUnknownInitial(t *testing.T) {
	wf := gearbox.NewWorkflow(gearbox.WorkflowConfig[fixtureEntity, string]{
		Entity:  "fixtures",
		Initial: []string{"ghost"},
		Load:    singleFixture(nil).Load, // any Load/Save; not exercised
		Save:    singleFixture(nil).Save,
	})
	publishOn(wf)
	err := wf.Validate()
	if err == nil || !strings.Contains(err.Error(), "Initial") {
		t.Fatalf("error = %v, want an Initial error", err)
	}
}

func TestWorkflow_TransitionsTwicePanics(t *testing.T) {
	wf := singleFixture(nil)
	a := publishOn(wf) // first Transitions call
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("second Transitions call did not panic")
		}
		if msg, ok := r.(string); ok && !strings.Contains(msg, "already defined") {
			t.Fatalf("panic = %q, want an already-defined panic", msg)
		}
	}()
	wf.Transitions(gearbox.Transitions[string]{fxReady: {a.To(fxCompleted)}})
}

func TestWorkflow_DuplicateEdgePanics(t *testing.T) {
	wf := singleFixture(nil)
	a := gearbox.NewAction(wf, gearbox.ActionConfig{Name: "Dup"}, gearbox.Noop[fixtureEntity, struct{}])
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("two edges for one action under one status did not panic")
		}
		if msg, ok := r.(string); ok && !strings.Contains(msg, "duplicate edge") {
			t.Fatalf("panic = %q, want a duplicate-edge panic", msg)
		}
	}()
	wf.Transitions(gearbox.Transitions[string]{fxDraft: {a.To(fxReady), a.To(fxFailed)}})
}

func TestWorkflow_ForeignActionPanics(t *testing.T) {
	other := singleFixture(nil)
	foreign := gearbox.NewAction(other, gearbox.ActionConfig{Name: "Foreign"}, gearbox.Noop[fixtureEntity, struct{}])
	wf := singleFixture(nil)
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("edge referencing another workflow's action did not panic")
		}
		if msg, ok := r.(string); ok && !strings.Contains(msg, "another workflow") {
			t.Fatalf("panic = %q, want an another-workflow panic", msg)
		}
	}()
	wf.Transitions(gearbox.Transitions[string]{fxDraft: {foreign.To(fxReady)}})
}

func TestWorkflow_DuplicateActionNamePanics(t *testing.T) {
	wf := singleFixture(&fixtureEntity{ID: "e1", Status: fxDraft})
	publishOn(wf)
	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("duplicate action name did not panic")
		}
		if msg, ok := r.(string); ok && !strings.Contains(msg, "duplicate action name") {
			t.Fatalf("panic = %q, want a duplicate-action-name panic", msg)
		}
	}()
	publishOn(wf) // same name again
}

func TestWorkflow_GraphAndDescriptorRoundtrip(t *testing.T) {
	wf := singleFixture(&fixtureEntity{ID: "e1", Status: fxDraft})
	a := gearbox.NewAction(wf, gearbox.ActionConfig{Name: "Publish", Role: "editor"},
		gearbox.Noop[fixtureEntity, struct{}])
	touch := gearbox.NewAction(wf, gearbox.ActionConfig{Name: "Touch"}, gearbox.Noop[fixtureEntity, struct{}])
	wf.Transitions(gearbox.Transitions[string]{
		fxDraft: {a.To(fxCompleted), touch.Stay()},
		fxReady: {a.To(fxCompleted)},
	})

	g := wf.Graph()
	if g.Entity != "fixtures" || g.WorkflowName != "default" || g.StatusColumn != "status" {
		t.Fatalf("graph header = %q/%q/%q", g.Entity, g.WorkflowName, g.StatusColumn)
	}
	// Status set derives from the map: keys ∪ targets, sorted.
	if got, want := strings.Join(g.Statuses, ","), "completed,draft,ready"; got != want {
		t.Fatalf("derived statuses = %q, want %q", got, want)
	}
	if len(g.Actions) != 2 {
		t.Fatalf("Graph.Actions has %d entries, want 2", len(g.Actions))
	}

	d := a.Descriptor()
	if d.Workflow != "fixtures" || d.Name != "Publish" || d.Role != "editor" {
		t.Fatalf("descriptor = %q.%q role=%q", d.Workflow, d.Name, d.Role)
	}
	if len(d.Edges) != 2 || d.Edges[fxDraft] != fxCompleted || d.Edges[fxReady] != fxCompleted {
		t.Fatalf("Descriptor.Edges = %v", d.Edges)
	}
	if d.RequestType != "struct {}" || d.ResponseType != "struct {}" {
		t.Fatalf("req/resp types = %q/%q", d.RequestType, d.ResponseType)
	}
	// A Stay edge surfaces as an empty target.
	if td := touch.Descriptor(); td.Edges[fxDraft] != "" {
		t.Fatalf("Stay edge target = %q, want empty", td.Edges[fxDraft])
	}
}
