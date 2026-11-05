package features_test

import (
	"context"
	"errors"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/mathis-sperlich/gearbox"
	"github.com/mathis-sperlich/gearbox/authjwt"
	"github.com/mathis-sperlich/gearbox/kit/features"
)

// flag stands in for a generated proto enum.
type flag int32

const (
	flagUnspecified flag = 0
	flagReports     flag = 1
	flagSheets      flag = 2
)

var (
	flagName  = map[int32]string{0: "FLAG_UNSPECIFIED", 1: "FLAG_REPORTS", 2: "FLAG_SHEETS"}
	flagValue = map[string]int32{"FLAG_UNSPECIFIED": 0, "FLAG_REPORTS": 1, "FLAG_SHEETS": 2}
)

func (f flag) String() string {
	if n, ok := flagName[int32(f)]; ok {
		return n
	}
	return strconv.Itoa(int(f))
}

func registry(t *testing.T) *features.Registry[flag] {
	t.Helper()
	r, err := features.NewRegistry[flag](flagValue)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

const (
	orgA = "aaaaaaaa-1111-1111-1111-111111111111"
	orgB = "bbbbbbbb-2222-2222-2222-222222222222"
)

// claim builds a raw claim map the way Verify delivers it (JSON round-trip).
func claim(buckets map[string]map[string]bool) map[string]any {
	fs := map[string]any{}
	for bucket, decisions := range buckets {
		m := map[string]any{}
		for name, on := range decisions {
			m[name] = on
		}
		fs[bucket] = m
	}
	return map[string]any{features.ClaimName: fs}
}

func TestRegistry(t *testing.T) {
	r := registry(t)
	if !r.Known(flagSheets) || r.Known(flagUnspecified) || r.Known(flag(99)) {
		t.Fatal("Known misclassifies values")
	}
	if f, ok := r.Lookup("FLAG_REPORTS"); !ok || f != flagReports {
		t.Fatalf("Lookup = %v, %v", f, ok)
	}
	if _, ok := r.Lookup("FLAG_UNSPECIFIED"); ok {
		t.Fatal("zero value looked up as a feature")
	}
	if got := r.Names(); !reflect.DeepEqual(got, []string{"FLAG_REPORTS", "FLAG_SHEETS"}) {
		t.Fatalf("Names = %v", got)
	}
	got := r.Unknown([]string{"FLAG_SHEETS", "FLAG_TYPO", "FLAG_UNSPECIFIED", "FLAG_TYPO"})
	if !reflect.DeepEqual(got, []string{"FLAG_TYPO", "FLAG_UNSPECIFIED"}) {
		t.Fatalf("Unknown = %v", got)
	}

	if _, err := features.NewRegistry[flag](map[string]int32{"FLAG_WRONG": 1}); err == nil {
		t.Fatal("a name String() disagrees with was accepted")
	}
	if _, err := features.NewRegistry[flag](map[string]int32{"FLAG_UNSPECIFIED": 0}); err == nil {
		t.Fatal("an enum with only a zero value was accepted")
	}
}

func TestFromClaims(t *testing.T) {
	if got := features.FromClaims(nil); len(got) != 0 {
		t.Fatalf("nil claims: %v", got)
	}
	if got := features.FromClaims(map[string]any{"sub": "x"}); len(got) != 0 {
		t.Fatalf("absent claim: %v", got)
	}
	got := features.FromClaims(map[string]any{features.ClaimName: map[string]any{
		orgA:      map[string]any{"FLAG_SHEETS": true, "junk": "notabool"},
		"badtype": "notamap",
	}})
	if v, ok := got[orgA]["FLAG_SHEETS"]; !ok || !v {
		t.Fatalf("valid decision dropped: %v", got)
	}
	if _, ok := got[orgA]["junk"]; ok {
		t.Fatal("non-bool decision kept")
	}
	if _, ok := got["badtype"]; ok {
		t.Fatal("non-map bucket kept")
	}
	// An in-process claim map (not JSON round-tripped) parses the same.
	inproc := features.FromClaims(map[string]any{features.ClaimName: map[string]map[string]bool{orgA: {"FLAG_SHEETS": true}}})
	if !inproc.Enabled("FLAG_SHEETS", orgA) {
		t.Fatalf("in-process claim: %v", inproc)
	}
}

func TestEnabledPrecedence(t *testing.T) {
	const f = "FLAG_SHEETS"
	cases := []struct {
		name    string
		buckets map[string]map[string]bool
		want    bool
	}{
		{"no decisions → off", nil, false},
		{"silent on this feature → off", map[string]map[string]bool{orgA: {"FLAG_REPORTS": true}}, false},
		{"scope grant → on", map[string]map[string]bool{orgA: {f: true}}, true},
		{"scope denial → off", map[string]map[string]bool{orgA: {f: false}}, false},
		{"global grant applies when scope silent", map[string]map[string]bool{features.GlobalBucket: {f: true}}, true},
		{"scope denial beats global grant", map[string]map[string]bool{orgA: {f: false}, features.GlobalBucket: {f: true}}, false},
		{"scope grant beats global denial", map[string]map[string]bool{orgA: {f: true}, features.GlobalBucket: {f: false}}, true},
		{"another scope's grant does not leak", map[string]map[string]bool{orgB: {f: true}}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := features.FromClaims(claim(tc.buckets)).Enabled(f, orgA); got != tc.want {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
	global := features.FromClaims(claim(map[string]map[string]bool{features.GlobalBucket: {f: true}}))
	for _, junk := range []string{"", features.GlobalBucket} {
		if global.Enabled(f, junk) {
			t.Fatalf("scope %q reached the global grant", junk)
		}
	}
	if !global.EnabledGlobally(f) || global.EnabledGlobally("FLAG_REPORTS") {
		t.Fatal("EnabledGlobally misreads the global bucket")
	}
}

func TestUUIDScope(t *testing.T) {
	for name, in := range map[string]string{
		"canonical":   orgA,
		"upper case":  "AAAAAAAA-1111-1111-1111-111111111111",
		"braced":      "{aaaaaaaa-1111-1111-1111-111111111111}",
		"urn":         "urn:uuid:aaaaaaaa-1111-1111-1111-111111111111",
		"URN upper":   "URN:UUID:AAAAAAAA-1111-1111-1111-111111111111",
		"no hyphens":  "aaaaaaaa111111111111111111111111",
		"mixed+brace": "{AaAaAaAa-1111-1111-1111-111111111111}",
	} {
		if got, ok := features.UUIDScope(in); !ok || got != orgA {
			t.Errorf("%s %q → %q, %v; want %q", name, in, got, ok, orgA)
		}
	}
	for _, junk := range []string{
		"", "*", "not-a-uuid",
		"gaaaaaaa-1111-1111-1111-111111111111",          // non-hex
		"aaaaaaaa1111-1111-1111-1111-111111111111"[:36], // hyphens misplaced
		"(aaaaaaaa-1111-1111-1111-111111111111)",
		"urn:uuix:aaaaaaaa-1111-1111-1111-111111111111",
		"aaaaaaaa-1111-1111-1111-11111111111z",
	} {
		if got, ok := features.UUIDScope(junk); ok {
			t.Errorf("%q accepted as %q", junk, got)
		}
	}
}

// Embed puts the resolver's decisions into a minted token; the verified
// token's claims resolve the same way. Unknown names are dropped.
func TestEmbed_RoundTripsThroughMintAndVerify(t *testing.T) {
	r := registry(t)
	v, err := authjwt.NewVerifier("features-test-secret-features-test-0")
	if err != nil {
		t.Fatal(err)
	}
	var gotPrincipal gearbox.Principal
	resolve := func(_ context.Context, p gearbox.Principal) (features.Decisions, error) {
		gotPrincipal = p
		return features.Decisions{
			orgA:                  {"FLAG_SHEETS": true, "FLAG_GONE": true},
			orgB:                  {"FLAG_GONE": true},
			features.GlobalBucket: {"FLAG_REPORTS": true},
		}, nil
	}
	mc := authjwt.MintClaims{Subject: "user-1", Extra: map[string]any{"email": "a@b.c"}}
	if err := r.Embed(context.Background(), resolve, "principal", &mc); err != nil {
		t.Fatal(err)
	}
	if gotPrincipal != "principal" {
		t.Fatalf("resolver saw %v", gotPrincipal)
	}
	tok, _, err := v.Mint(mc, time.Hour, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	c, err := v.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	d := features.FromClaims(c.Raw)
	want := features.Decisions{orgA: {"FLAG_SHEETS": true}, features.GlobalBucket: {"FLAG_REPORTS": true}}
	if !reflect.DeepEqual(d, want) {
		t.Fatalf("decisions = %v, want %v", d, want)
	}
	if c.Raw["email"] != "a@b.c" {
		t.Fatal("Embed clobbered other extras")
	}
	if !d.Enabled("FLAG_SHEETS", orgA) || !d.Enabled("FLAG_REPORTS", orgB) || d.Enabled("FLAG_SHEETS", orgB) {
		t.Fatalf("resolution after round trip wrong: %v", d)
	}
}

func TestEmbed_Errors(t *testing.T) {
	r := registry(t)
	var mc authjwt.MintClaims
	if err := r.Embed(context.Background(), nil, nil, &mc); err == nil {
		t.Fatal("nil resolver accepted")
	}
	boom := errors.New("boom")
	err := r.Embed(context.Background(), func(context.Context, gearbox.Principal) (features.Decisions, error) {
		return nil, boom
	}, nil, &mc)
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want wrapped boom", err)
	}
	if _, set := mc.Extra[features.ClaimName]; set {
		t.Fatal("claim written despite resolver error")
	}
}

func TestAssertKnown_DB(t *testing.T) {
	url := os.Getenv("GEARBOX_TEST_DATABASE_URL")
	if url == "" {
		t.Skip("GEARBOX_TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, url)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	// A temp table inside a rolled-back tx: nothing outlives the test.
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `create temp table feature_access (feature text not null) on commit drop`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(ctx, `insert into feature_access values ('FLAG_SHEETS'), ('FLAG_REPORTS'), ('FLAG_SHEETS')`); err != nil {
		t.Fatal(err)
	}
	r := registry(t)
	if err := r.AssertKnown(ctx, tx, ""); err != nil {
		t.Fatalf("known names refused: %v", err)
	}
	if _, err := tx.Exec(ctx, `insert into feature_access values ('FLAG_TYPO'), ('FLAG_UNSPECIFIED')`); err != nil {
		t.Fatal(err)
	}
	err = r.AssertKnown(ctx, tx, "")
	if err == nil || !strings.Contains(err.Error(), "FLAG_TYPO") || !strings.Contains(err.Error(), "FLAG_UNSPECIFIED") {
		t.Fatalf("err = %v, want both unknown names", err)
	}
	if err := r.AssertKnown(ctx, tx, `select 'FLAG_SHEETS'::text`); err != nil {
		t.Fatalf("custom query: %v", err)
	}
	if err := r.AssertKnown(ctx, tx, `select nope from nowhere`); err == nil {
		t.Fatal("query error swallowed")
	}
}
