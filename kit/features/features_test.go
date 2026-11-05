package features_test

import (
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

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

func newRegistry(t *testing.T) *features.Registry[flag] {
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

const testSecret = "features-test-secret-features-test-0"

func newVerifier(t *testing.T) authjwt.Signer {
	t.Helper()
	v, err := authjwt.NewVerifier(testSecret)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func TestEmbed_RoundTripsThroughSignAndVerify(t *testing.T) {
	// Given decisions resolved at sign-in, embedded next to another extra
	v := newVerifier(t)
	resolved := features.Decisions{
		orgA:                  {"FLAG_SHEETS": true},
		features.GlobalBucket: {"FLAG_REPORTS": true},
	}
	signIn := authjwt.ClaimsSet{Subject: "user-1", Extra: map[string]any{"email": "a@b.c"}}
	resolved.Embed(&signIn)

	// When the token is signed, verified and its decisions read back
	token, _, err := v.Sign(signIn, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := v.Verify(token)
	if err != nil {
		t.Fatal(err)
	}
	got, err := features.FromClaims(verified.Raw)

	// Then they are the decisions that went in, and other extras survive
	if err != nil || !reflect.DeepEqual(got, resolved) {
		t.Fatalf("FromClaims = %v, %v; want %v", got, err, resolved)
	}
	if verified.Raw["email"] != "a@b.c" {
		t.Fatal("Embed clobbered another extra")
	}
}

func TestEmbed_StartsExtraWhenNil(t *testing.T) {
	// Given claims with no extras
	var signIn authjwt.ClaimsSet
	// When decisions are embedded
	features.Decisions{orgA: {"FLAG_SHEETS": true}}.Embed(&signIn)
	// Then the claim is set
	if _, ok := signIn.Extra[features.ClaimName]; !ok {
		t.Fatal("claim not written")
	}
}

func TestEnabled_Precedence(t *testing.T) {
	// Given decisions for orgA, the global bucket, and another org
	precedenceCases := []struct {
		name      string
		decisions features.Decisions
		want      bool
	}{
		{"scope grant is on", features.Decisions{orgA: {"FLAG_SHEETS": true}}, true},
		{"global grant applies when the scope is silent", features.Decisions{features.GlobalBucket: {"FLAG_SHEETS": true}}, true},
		{"scope grant beats global denial", features.Decisions{orgA: {"FLAG_SHEETS": true}, features.GlobalBucket: {"FLAG_SHEETS": false}}, true},
		{"no decisions is off", nil, false},
		{"silence on this feature is off", features.Decisions{orgA: {"FLAG_REPORTS": true}}, false},
		{"scope denial is off", features.Decisions{orgA: {"FLAG_SHEETS": false}}, false},
		{"scope denial beats global grant", features.Decisions{orgA: {"FLAG_SHEETS": false}, features.GlobalBucket: {"FLAG_SHEETS": true}}, false},
		{"another scope's grant does not leak", features.Decisions{orgB: {"FLAG_SHEETS": true}}, false},
	}
	for _, tc := range precedenceCases {
		t.Run(tc.name, func(t *testing.T) {
			// When FLAG_SHEETS is checked in orgA
			got := tc.decisions.Enabled(flagSheets, orgA)
			// Then the most specific decision wins, else off
			if got != tc.want {
				t.Fatalf("Enabled = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEnabled_ScopesNamingNoTenantAreOff(t *testing.T) {
	// Given a global grant
	globalGrant := features.Decisions{features.GlobalBucket: {"FLAG_SHEETS": true}}
	scopesNamingNoTenant := []string{"", features.GlobalBucket}
	for _, scope := range scopesNamingNoTenant {
		// When the feature is checked in a scope that names no tenant
		// Then the global grant is not reachable
		if globalGrant.Enabled(flagSheets, scope) {
			t.Errorf("scope %q reached the global grant", scope)
		}
	}
}

func TestFromClaims_AbsentClaimHasNoDecisions(t *testing.T) {
	// Given verified claims without a features claim
	withoutFeatures := map[string]any{"sub": "user-1"}
	// When they are converted
	got, err := features.FromClaims(withoutFeatures)
	// Then there are no decisions and no error
	if err != nil || len(got) != 0 {
		t.Fatalf("FromClaims = %v, %v", got, err)
	}
}

func TestFromClaims_RejectsShapesWeNeverSign(t *testing.T) {
	// Given features claims of shapes the app never signs
	malformedClaims := map[string]any{
		"not an object":       "FLAG_SHEETS",
		"bucket not a map":    map[string]any{orgA: "FLAG_SHEETS"},
		"decision not a bool": map[string]any{orgA: map[string]any{"FLAG_SHEETS": "yes"}},
	}
	for name, claim := range malformedClaims {
		// When they are converted
		_, err := features.FromClaims(map[string]any{features.ClaimName: claim})
		// Then it is an error
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

func TestNewRegistry_KnowsEveryNonZeroValue(t *testing.T) {
	// Given the registry of the flag enum
	r := newRegistry(t)
	// When its values are asked about
	// Then the non-zero ones are features, zero and undefined ones are not
	if !r.Known(flagReports) || !r.Known(flagSheets) {
		t.Fatal("defined feature unknown")
	}
	if r.Known(flagUnspecified) || r.Known(flag(99)) {
		t.Fatal("zero or undefined value known")
	}
}

func TestNewRegistry_OnlyZeroIsValid(t *testing.T) {
	// Given an enum with no features yet
	onlyUnspecified := map[string]int32{"FLAG_UNSPECIFIED": 0}
	// When a registry is built
	r, err := features.NewRegistry[flag](onlyUnspecified)
	// Then it is valid and knows nothing
	if err != nil || r.Known(flagSheets) {
		t.Fatalf("NewRegistry = %v", err)
	}
}

func TestNewRegistry_RefusesNamesStringDisagreesWith(t *testing.T) {
	// Given a name map that disagrees with the enum's String
	misnamed := map[string]int32{"FLAG_UNSPECIFIED": 0, "FLAG_WRONG": 1}
	// When a registry is built
	_, err := features.NewRegistry[flag](misnamed)
	// Then it fails hard
	if err == nil {
		t.Fatal("accepted")
	}
}

// zeroReports names zero FLAG_REPORTS, so String agrees with the map but the
// zero value is a real feature.
type zeroReports int32

func (zeroReports) String() string { return "FLAG_REPORTS" }

func TestNewRegistry_RefusesAFeatureAtZero(t *testing.T) {
	// Given an enum whose zero value is a real feature
	featureAtZero := map[string]int32{"FLAG_REPORTS": 0}
	// When a registry is built
	_, err := features.NewRegistry[zeroReports](featureAtZero)
	// Then it fails hard, naming the rule
	if err == nil || !strings.Contains(err.Error(), "_UNSPECIFIED") {
		t.Fatalf("err = %v", err)
	}
}

func TestAssertKnown_AcceptsDefinedNames(t *testing.T) {
	// Given stored names the enum defines, with duplicates
	stored := []string{"FLAG_SHEETS", "FLAG_REPORTS", "FLAG_SHEETS"}
	// When they are checked
	err := newRegistry(t).AssertKnown(stored)
	// Then boot proceeds
	if err != nil {
		t.Fatal(err)
	}
}

func TestAssertKnown_NamesEveryUnknownOnce(t *testing.T) {
	// Given stored names with a typo (twice) and the zero value's name
	stored := []string{"FLAG_SHEETS", "FLAG_TYPO", "FLAG_UNSPECIFIED", "FLAG_TYPO"}
	// When they are checked
	err := newRegistry(t).AssertKnown(stored)
	// Then the error lists each unknown name once, sorted
	if err == nil || !strings.HasSuffix(err.Error(), "[FLAG_TYPO FLAG_UNSPECIFIED]") {
		t.Fatalf("err = %v", err)
	}
}
