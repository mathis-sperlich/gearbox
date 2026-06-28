package gearbox_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/mathis-sperlich/gearbox"
)

func TestRunInTx_SuccessTransitionsAndSaves(t *testing.T) {
	ent := &fixtureEntity{ID: "e1", Status: fxDraft}
	a := publishOn(singleFixture(ent))
	eng, _ := allowAllEngine(nilTx{})

	if _, err := gearbox.RunInTx(context.Background(), nilTx{}, eng, a, "e1", struct{}{}); err != nil {
		t.Fatalf("RunInTx: %v", err)
	}
	if ent.Status != fxReady {
		t.Fatalf("status = %q, want ready", ent.Status)
	}
	if !ent.Saved {
		t.Fatal("entity not saved")
	}
}

func TestRunInTx_BodyErrorRollsBack(t *testing.T) {
	ent := &fixtureEntity{ID: "e1", Status: fxDraft}
	wf := singleFixture(ent)
	bodyErr := errors.New("boom")
	a := gearbox.NewAction(wf, gearbox.ActionConfig{Name: "Fail"},
		func(_ context.Context, _ *gearbox.DB, _ *fixtureEntity, _ struct{}) (struct{}, error) {
			return struct{}{}, bodyErr
		})
	wf.Transitions(gearbox.Transitions[string]{fxDraft: {a.To(fxReady)}})
	eng, _ := allowAllEngine(nilTx{})

	_, err := gearbox.RunInTx(context.Background(), nilTx{}, eng, a, "e1", struct{}{})
	if !errors.Is(err, bodyErr) {
		t.Fatalf("err = %v, want bodyErr", err)
	}
	if ent.Status != fxDraft {
		t.Fatalf("status = %q, want unchanged draft", ent.Status)
	}
	if ent.Saved {
		t.Fatal("entity was saved despite a body error")
	}
}

func TestRunInTx_StayEdgeKeepsStatus(t *testing.T) {
	ent := &fixtureEntity{ID: "e1", Status: fxReady}
	wf := singleFixture(ent)
	a := gearbox.NewAction(wf, gearbox.ActionConfig{Name: "Touch"}, gearbox.Noop[fixtureEntity, struct{}])
	wf.Transitions(gearbox.Transitions[string]{
		fxDraft: {a.Stay()},
		fxReady: {a.Stay()},
	})
	eng, _ := allowAllEngine(nilTx{})

	if _, err := gearbox.RunInTx(context.Background(), nilTx{}, eng, a, "e1", struct{}{}); err != nil {
		t.Fatalf("RunInTx: %v", err)
	}
	if ent.Status != fxReady {
		t.Fatalf("status = %q, want unchanged ready (Stay edge)", ent.Status)
	}
	if !ent.Saved {
		t.Fatal("a Stay action should still Save the entity")
	}
}

func TestRunInTx_WrongFromStatus(t *testing.T) {
	ent := &fixtureEntity{ID: "e1", Status: fxCompleted} // not draft
	a := publishOn(singleFixture(ent))
	eng, _ := allowAllEngine(nilTx{})

	_, err := gearbox.RunInTx(context.Background(), nilTx{}, eng, a, "e1", struct{}{})
	if !errors.Is(err, gearbox.ErrInvalidTransition) {
		t.Fatalf("err = %v, want ErrInvalidTransition", err)
	}
	if ent.Saved {
		t.Fatal("entity was saved despite an invalid transition")
	}
}

func TestRunInTx_EntityNotFound(t *testing.T) {
	a := publishOn(singleFixture(nil)) // Load returns pgx.ErrNoRows
	eng, _ := allowAllEngine(nilTx{})

	_, err := gearbox.RunInTx(context.Background(), nilTx{}, eng, a, "missing", struct{}{})
	if !errors.Is(err, gearbox.ErrEntityNotFound) {
		t.Fatalf("err = %v, want ErrEntityNotFound", err)
	}
}

func TestRunInTx_MultiSourceAcceptsEachAndRejectsNonMember(t *testing.T) {
	cancelOn := func(wf *gearbox.Workflow[fixtureEntity, string]) *gearbox.Action[fixtureEntity, string, struct{}, struct{}] {
		a := gearbox.NewAction(wf, gearbox.ActionConfig{Name: "Cancel"}, gearbox.Noop[fixtureEntity, struct{}])
		wf.Transitions(gearbox.Transitions[string]{
			fxDraft: {a.To(fxFailed)},
			fxReady: {a.To(fxFailed)},
		})
		return a
	}
	eng, _ := allowAllEngine(nilTx{})

	for _, from := range []string{fxDraft, fxReady} {
		ent := &fixtureEntity{ID: "e1", Status: from}
		a := cancelOn(singleFixture(ent))
		if _, err := gearbox.RunInTx(context.Background(), nilTx{}, eng, a, "e1", struct{}{}); err != nil {
			t.Fatalf("RunInTx from %q: %v", from, err)
		}
		if ent.Status != fxFailed {
			t.Fatalf("from %q: status = %q, want failed", from, ent.Status)
		}
	}

	ent := &fixtureEntity{ID: "e1", Status: fxCompleted}
	a := cancelOn(singleFixture(ent))
	_, err := gearbox.RunInTx(context.Background(), nilTx{}, eng, a, "e1", struct{}{})
	if !errors.Is(err, gearbox.ErrInvalidTransition) {
		t.Fatalf("err = %v, want ErrInvalidTransition for non-member status", err)
	}
}

func TestRunInTx_SourceAttributionIsFirstExec(t *testing.T) {
	ent := &fixtureEntity{ID: "e1", Status: fxDraft}
	a := publishOn(singleFixture(ent))

	rec := newRecordingTx()
	runner := txRunner(rec)
	eng := engineOver(runner, gearbox.Config{
		Source:    gearbox.GUCSourceWriter{GUC: "gearbox.source"},
		RequestID: func(context.Context) string { return "req-xyz" },
	})

	if _, err := gearbox.RunInTx(context.Background(), rec, eng, a, "e1", struct{}{}); err != nil {
		t.Fatalf("RunInTx: %v", err)
	}
	if len(rec.Calls) < 2 {
		t.Fatalf("expected at least 2 Exec calls (set_config + lock), got %d", len(rec.Calls))
	}
	if rec.Calls[0].SQL != "select set_config($1, $2, true)" {
		t.Fatalf("first Exec = %q, want set_config", rec.Calls[0].SQL)
	}
	json, ok := rec.Calls[0].Args[1].(string)
	if !ok || !strings.Contains(json, "req-xyz") {
		t.Fatalf("source JSON = %v, want it to carry request id req-xyz", rec.Calls[0].Args[1])
	}
	if !strings.Contains(rec.Calls[1].SQL, "FOR UPDATE") {
		t.Fatalf("second Exec = %q, want the row lock", rec.Calls[1].SQL)
	}
}

// The composition pattern: several RunInTx calls share one caller-owned tx.
func TestRunInTx_ComposesInOneTx(t *testing.T) {
	e1 := &fixtureEntity{ID: "a", Status: fxDraft}
	e2 := &fixtureEntity{ID: "b", Status: fxDraft}
	a1 := publishOn(singleFixture(e1))
	a2 := publishOn(singleFixture(e2))
	eng, _ := allowAllEngine(nilTx{})

	tx := nilTx{}
	for _, step := range []func() error{
		func() error {
			_, err := gearbox.RunInTx(context.Background(), tx, eng, a1, "a", struct{}{})
			return err
		},
		func() error {
			_, err := gearbox.RunInTx(context.Background(), tx, eng, a2, "b", struct{}{})
			return err
		},
	} {
		if err := step(); err != nil {
			t.Fatal(err)
		}
	}
	if e1.Status != fxReady || e2.Status != fxReady {
		t.Fatalf("statuses = %q/%q, want ready/ready", e1.Status, e2.Status)
	}
}
