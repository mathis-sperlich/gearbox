package features_test

import (
	"encoding/json/v2"
	"strconv"
	"strings"
	"testing"

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

func TestEmbed_WritesTheFeaturesClaimNextToOtherExtras(t *testing.T) {
	// Given decisions resolved at sign-in and a claim set with another extra
	resolved := features.Decisions[flag]{
		Global:  features.Grants[flag]{flagReports: true},
		ByScope: map[string]features.Grants[flag]{orgA: {flagSheets: true}},
	}
	signIn := authjwt.ClaimsSet{Subject: "user-1", Extra: map[string]any{"email": "a@b.c"}}
	// When they are embedded
	resolved.Embed(&signIn)
	// Then the features claim holds them by name, "*" for global, and the other extra survives
	wantClaim := `{"*":{"FLAG_REPORTS":true},"` + orgA + `":{"FLAG_SHEETS":true}}`
	if got := claimJSON(t, signIn); got != wantClaim {
		t.Fatalf("features claim = %s, want %s", got, wantClaim)
	}
	if signIn.Extra["email"] != "a@b.c" {
		t.Fatal("Embed clobbered another extra")
	}
}

func TestEmbed_StartsExtraWhenNil(t *testing.T) {
	// Given claims with no extras
	var signIn authjwt.ClaimsSet
	// When decisions are embedded
	features.Decisions[flag]{Global: features.Grants[flag]{flagSheets: true}}.Embed(&signIn)
	// Then the claim is set
	if _, ok := signIn.Extra["features"]; !ok {
		t.Fatal("claim not written")
	}
}

func TestEnabled_Precedence(t *testing.T) {
	// Given decisions for orgA, the global bucket, and another org
	precedenceCases := []struct {
		name      string
		decisions features.Decisions[flag]
		want      bool
	}{
		{"scope grant is on", inScope(orgA, flagSheets, true), true},
		{"global grant applies when the scope is silent", global(flagSheets, true), true},
		{"scope grant beats global denial", both(orgA, flagSheets, true, false), true},
		{"no decisions is off", features.Decisions[flag]{}, false},
		{"silence on this feature is off", inScope(orgA, flagReports, true), false},
		{"scope denial is off", inScope(orgA, flagSheets, false), false},
		{"scope denial beats global grant", both(orgA, flagSheets, false, true), false},
		{"another scope's grant does not leak", inScope(orgB, flagSheets, true), false},
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
	globalGrant := global(flagSheets, true)
	scopesNamingNoTenant := []string{"", "*"}
	for _, scope := range scopesNamingNoTenant {
		// When the feature is checked in a scope that names no tenant
		// Then the global grant is not reachable
		if globalGrant.Enabled(flagSheets, scope) {
			t.Errorf("scope %q reached the global grant", scope)
		}
	}
}

func TestNewGate_AcceptsAnEnumWithNoFeaturesYet(t *testing.T) {
	// Given an enum whose only value is the zero one, and nothing to gate
	onlyUnspecified := map[string]int32{"FLAG_UNSPECIFIED": 0}
	// When a gate is built
	_, err := features.NewGate(features.Gate[flag]{Enum: onlyUnspecified, ScopeField: scopeField})
	// Then it is valid
	if err != nil {
		t.Fatalf("NewGate = %v", err)
	}
}

func TestNewGate_RefusesNamesStringDisagreesWith(t *testing.T) {
	// Given a name map that disagrees with the enum's String
	misnamed := map[string]int32{"FLAG_UNSPECIFIED": 0, "FLAG_WRONG": 1}
	// When a gate is built
	_, err := features.NewGate(features.Gate[flag]{Enum: misnamed, ScopeField: scopeField})
	// Then it fails hard
	if err == nil {
		t.Fatal("accepted")
	}
}

// zeroReports names zero FLAG_REPORTS, so String agrees with the map but the
// zero value is a real feature.
type zeroReports int32

func (zeroReports) String() string { return "FLAG_REPORTS" }

func TestNewGate_RefusesAFeatureAtZero(t *testing.T) {
	// Given an enum whose zero value is a real feature
	featureAtZero := map[string]int32{"FLAG_REPORTS": 0}
	// When a gate is built
	_, err := features.NewGate(features.Gate[zeroReports]{Enum: featureAtZero, ScopeField: scopeField})
	// Then it fails hard, naming the rule
	if err == nil || !strings.Contains(err.Error(), "_UNSPECIFIED") {
		t.Fatalf("err = %v", err)
	}
}

func TestAssertKnown_AcceptsDefinedNames(t *testing.T) {
	// Given stored names the enum defines, with duplicates
	stored := []string{"FLAG_SHEETS", "FLAG_REPORTS", "FLAG_SHEETS"}
	// When they are checked
	err := features.AssertKnown[flag](flagValue, stored)
	// Then boot proceeds
	if err != nil {
		t.Fatal(err)
	}
}

func TestAssertKnown_NamesEveryUnknownOnce(t *testing.T) {
	// Given stored names with a typo (twice) and the zero value's name
	stored := []string{"FLAG_SHEETS", "FLAG_TYPO", "FLAG_UNSPECIFIED", "FLAG_TYPO"}
	// When they are checked
	err := features.AssertKnown[flag](flagValue, stored)
	// Then the error lists each unknown name once, sorted
	if err == nil || !strings.HasSuffix(err.Error(), "[FLAG_TYPO FLAG_UNSPECIFIED]") {
		t.Fatalf("err = %v", err)
	}
}

// claimJSON is the "features" claim Embed wrote into c, as JSON.
func claimJSON(t *testing.T, c authjwt.ClaimsSet) string {
	t.Helper()
	b, err := json.Marshal(c.Extra["features"], json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// inScope grants f in scope only; global grants it everywhere; both does
// both, the scope's decision first.
func inScope(scope string, f flag, on bool) features.Decisions[flag] {
	return features.Decisions[flag]{ByScope: map[string]features.Grants[flag]{scope: {f: on}}}
}

func global(f flag, on bool) features.Decisions[flag] {
	return features.Decisions[flag]{Global: features.Grants[flag]{f: on}}
}

func both(scope string, f flag, inScopeOn, globalOn bool) features.Decisions[flag] {
	d := inScope(scope, f, inScopeOn)
	d.Global = features.Grants[flag]{f: globalOn}
	return d
}

func TestEmbed_DropsAScopeNamedStar(t *testing.T) {
	// Given decisions whose ByScope names "*", which Enabled never resolves
	starScoped := features.Decisions[flag]{ByScope: map[string]features.Grants[flag]{"*": {flagSheets: true}}}
	var signIn authjwt.ClaimsSet
	// When they are embedded
	starScoped.Embed(&signIn)
	// Then the claim carries no global grant from it
	if got := claimJSON(t, signIn); got != `{}` {
		t.Fatalf("features claim = %s, want {}", got)
	}
}
