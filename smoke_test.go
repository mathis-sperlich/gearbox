package gearbox_test

import (
	"context"
	"errors"
	"testing"

	"github.com/mathis-sperlich/gearbox"
)

// publishOn wires a fixture action (draft -> ready) plus the transition map.
func publishOn(wf *gearbox.Workflow[fixtureEntity, string]) *gearbox.Action[fixtureEntity, string, struct{}, struct{}] {
	a := gearbox.NewAction(wf, gearbox.ActionConfig{Name: "Publish"}, gearbox.Noop[fixtureEntity, struct{}])
	wf.Transitions(gearbox.Transitions[string]{fxDraft: {a.To(fxReady)}})
	return a
}

func TestSmoke_RunTransitions(t *testing.T) {
	ent := &fixtureEntity{ID: "e1", Status: fxDraft}
	a := publishOn(singleFixture(ent))

	eng, runner := allowAllEngine(nilTx{})
	if _, err := gearbox.Run(context.Background(), eng, nil, a, "e1", struct{}{}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if ent.Status != fxReady {
		t.Fatalf("status = %q, want ready", ent.Status)
	}
	if !ent.Saved {
		t.Fatal("entity not saved")
	}
	if runner.called != 1 {
		t.Fatalf("TxRunner called %d times, want 1", runner.called)
	}
}

func TestSmoke_AuthorizeDenialBlocksBody(t *testing.T) {
	ent := &fixtureEntity{ID: "e1", Status: fxDraft}
	a := publishOn(singleFixture(ent))

	deny := gearbox.Authorize(func(context.Context, gearbox.Principal, gearbox.ActionDescriptor, []string) error {
		return gearbox.ErrUnauthorized
	})
	runner := txRunner(nilTx{})
	eng := engineOver(runner, gearbox.Config{Authz: deny})

	_, err := gearbox.Run(context.Background(), eng, nil, a, "e1", struct{}{})
	if !errors.Is(err, gearbox.ErrUnauthorized) {
		t.Fatalf("err = %v, want ErrUnauthorized", err)
	}
	if runner.called != 0 {
		t.Fatal("TxRunner was called despite authorization denial")
	}
	if ent.Status != fxDraft || ent.Saved {
		t.Fatal("entity mutated despite authorization denial")
	}
}

func TestSmoke_InvalidTransitionIsTyped(t *testing.T) {
	ent := &fixtureEntity{ID: "e1", Status: fxReady} // not draft
	a := publishOn(singleFixture(ent))

	eng, _ := allowAllEngine(nilTx{})
	_, err := gearbox.Run(context.Background(), eng, nil, a, "e1", struct{}{})
	if !errors.Is(err, gearbox.ErrInvalidTransition) {
		t.Fatalf("err = %v, want ErrInvalidTransition", err)
	}
}

func TestSmoke_SourceWriterReceivesAttribution(t *testing.T) {
	ent := &fixtureEntity{ID: "e1", Status: fxDraft}
	a := publishOn(singleFixture(ent))

	rec := newRecordingTx()
	runner := txRunner(rec)
	eng := engineOver(runner, gearbox.Config{
		Source:    gearbox.GUCSourceWriter{GUC: "gearbox.source"},
		RequestID: func(context.Context) string { return "req-123" },
	})

	if _, err := gearbox.Run(context.Background(), eng, nil, a, "e1", struct{}{}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(rec.Calls) == 0 {
		t.Fatal("no Exec calls recorded")
	}
	if rec.Calls[0].SQL != "select set_config($1, $2, true)" {
		t.Fatalf("first Exec = %q, want set_config", rec.Calls[0].SQL)
	}
	if got := rec.Calls[0].Args[0]; got != "gearbox.source" {
		t.Fatalf("GUC arg = %v, want gearbox.source", got)
	}
}

// Compile-time assertion that Noop has the ActionFn shape.
var _ gearbox.ActionFn[fixtureEntity, struct{}, struct{}] = gearbox.Noop[fixtureEntity, struct{}]
