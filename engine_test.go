package gearbox_test

import (
	"context"
	"errors"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/mathis-sperlich/gearbox"
)

func TestEngine_AuthorizeDenialBlocksBodyAndNeverOpensTx(t *testing.T) {
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
		t.Fatalf("TxRunner.called = %d, want 0 (no tx opened on denial)", runner.called)
	}
	if ent.Status != fxDraft || ent.Saved {
		t.Fatal("entity mutated despite authorization denial")
	}
}

func TestEngine_PrincipalReachesTxRunnerAndAuthorize(t *testing.T) {
	ent := &fixtureEntity{ID: "e1", Status: fxDraft}
	a := publishOn(singleFixture(ent))

	type principal struct{ ID string }
	princ := &principal{ID: "user-42"}

	var seenByAuthz gearbox.Principal
	authz := gearbox.Authorize(func(_ context.Context, p gearbox.Principal, _ gearbox.ActionDescriptor, _ []string) error {
		seenByAuthz = p
		return nil
	})
	runner := txRunner(nilTx{})
	eng := engineOver(runner, gearbox.Config{Authz: authz})

	if _, err := gearbox.Run(context.Background(), eng, princ, a, "e1", struct{}{}); err != nil {
		t.Fatalf("Run: %v", err)
	}
	if runner.lastPrinc != gearbox.Principal(princ) {
		t.Fatalf("TxRunner saw principal %v, want %v", runner.lastPrinc, princ)
	}
	if seenByAuthz != gearbox.Principal(princ) {
		t.Fatalf("Authorize saw principal %v, want %v", seenByAuthz, princ)
	}
}

func TestEngine_NilAuthzAllows(t *testing.T) {
	ent := &fixtureEntity{ID: "e1", Status: fxDraft}
	a := publishOn(singleFixture(ent))

	runner := txRunner(nilTx{})
	eng := engineOver(runner, gearbox.Config{}) // no Authz => allow
	if _, err := gearbox.Run(context.Background(), eng, nil, a, "e1", struct{}{}); err != nil {
		t.Fatalf("Run with nil authz: %v", err)
	}
	if ent.Status != fxReady {
		t.Fatalf("status = %q, want ready (nil authz permitted the action)", ent.Status)
	}
}

// The bulk-composition gate: eng.Authorize consults the same policy Run does,
// so a handler can gate once before a RunInTx loop.
func TestEngine_AuthorizeMethodConsultsPolicy(t *testing.T) {
	a := publishOn(singleFixture(&fixtureEntity{ID: "e1", Status: fxDraft}))
	var gotIDs []string
	authz := gearbox.Authorize(func(_ context.Context, _ gearbox.Principal, d gearbox.ActionDescriptor, ids []string) error {
		gotIDs = ids
		if d.Name != "Publish" {
			return gearbox.ErrUnauthorized
		}
		return nil
	})
	eng := engineOver(txRunner(nilTx{}), gearbox.Config{Authz: authz})

	if err := eng.Authorize(context.Background(), nil, a, []string{"a", "b"}); err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	if len(gotIDs) != 2 {
		t.Fatalf("policy saw %d ids, want 2", len(gotIDs))
	}
}

// eng.Tx exposes the TxRunner for composed operations.
func TestEngine_TxOpensThroughRunner(t *testing.T) {
	runner := txRunner(nilTx{})
	eng := engineOver(runner, gearbox.Config{})
	if err := eng.Tx(context.Background(), "princ", func(pgx.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	if runner.called != 1 || runner.lastPrinc != gearbox.Principal("princ") {
		t.Fatalf("runner.called=%d lastPrinc=%v", runner.called, runner.lastPrinc)
	}
}
