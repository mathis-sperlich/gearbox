package gearbox_test

import (
	"context"
	"strings"
	"testing"

	"github.com/mathis-sperlich/gearbox"
)

// A workflow with only custom Load/Save still gets reflected status accessors
// and a derived LockSQL, and transitions correctly.
func TestDefaults_ReflectedStatusAndDerivedLock(t *testing.T) {
	ent := &fixtureEntity{ID: "e1", Status: fxDraft}
	wf := singleFixture(ent) // declares no StatusField/LockSQL
	if !strings.Contains(wf.LockSQL, "FOR UPDATE") || !strings.Contains(wf.LockSQL, `"fixtures"`) {
		t.Fatalf("derived LockSQL = %q", wf.LockSQL)
	}
	a := gearbox.NewAction(wf, gearbox.ActionConfig{Name: "D"}, gearbox.Noop[fixtureEntity, struct{}])
	wf.Transitions(gearbox.Transitions[string]{fxDraft: {a.To(fxReady)}})

	eng, _ := allowAllEngine(nilTx{})
	if _, err := gearbox.Run(context.Background(), eng, nil, a, "e1", struct{}{}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if ent.Status != fxReady {
		t.Fatalf("status = %q, want ready (reflected SetStatus did not write)", ent.Status)
	}
}

// StatusOf/SetStatus overrides carry a synthetic status (derived from a bool)
// with no reflection on any string field.
func TestDefaults_StatusAccessorOverrides(t *testing.T) {
	type flagged struct {
		ID   string
		Live bool
	}
	ent := &flagged{ID: "e1", Live: true}
	wf := gearbox.NewWorkflow(gearbox.WorkflowConfig[flagged, string]{
		Entity: "flags",
		StatusOf: func(e *flagged) string {
			if e.Live {
				return "on"
			}
			return "off"
		},
		SetStatus: func(e *flagged, s string) { e.Live = s == "on" },
		Load:      func(_ context.Context, _ *gearbox.DB, _ string) (*flagged, error) { return ent, nil },
		Save:      func(_ context.Context, _ *gearbox.DB, _ *flagged) error { return nil },
	})
	a := gearbox.NewAction(wf, gearbox.ActionConfig{Name: "Off"}, gearbox.Noop[flagged, struct{}])
	wf.Transitions(gearbox.Transitions[string]{"on": {a.To("off")}})

	eng, _ := allowAllEngine(nilTx{})
	if _, err := gearbox.Run(context.Background(), eng, nil, a, "e1", struct{}{}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if ent.Live {
		t.Fatal("SetStatus override did not flip the bool")
	}
}

func TestDefaults_NonStructEntityPanics(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic for a non-struct entity")
		}
	}()
	gearbox.NewWorkflow(gearbox.WorkflowConfig[string, string]{Entity: "x"})
}

func TestDefaults_MissingStatusFieldPanics(t *testing.T) {
	type noStatus struct{ ID string }
	defer func() {
		if recover() == nil {
			t.Fatal("expected panic: entity has no Status field")
		}
	}()
	gearbox.NewWorkflow(gearbox.WorkflowConfig[noStatus, string]{Entity: "x"})
}

// Derived Load/Save need db tags; a tagless entity fails at boot, not at request time.
func TestDefaults_DerivedCrudNeedsDBTagsAtBoot(t *testing.T) {
	type tagless struct {
		ID     string
		Status string
	}
	defer func() {
		if recover() == nil {
			t.Fatal("expected boot panic: tagless entity with derived Load/Save")
		}
	}()
	gearbox.NewWorkflow(gearbox.WorkflowConfig[tagless, string]{Entity: "tagless"})
}
