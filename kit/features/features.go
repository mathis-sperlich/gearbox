// Package features gates an app's features per tenant scope, keyed by the
// app's own proto feature enum.
//
// The app resolves a user's decisions once, when it signs their token, and
// Decisions.Embed writes them into the token as the "features" claim:
//
//	"features": { "<scope>": { "FEATURE_X": true, ... }, "*": { ... } }
//
// A scope is whatever the app tenants by (an organisation id), spelled
// exactly as requests name it — the app signs the keys, so lookups are plain
// map reads. "*" holds decisions for every scope; a global grant is how a
// feature goes GA. Only explicit decisions appear; anything absent is off.
//
// Checks never touch the database: the Gate and Decisions.Enabled read the
// claims connectgear's AuthInterceptor already verified and holds in memory.
// A decision is therefore as fresh as the token (bounded by its TTL).
package features

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"

	"github.com/mathis-sperlich/gearbox/authjwt"
)

// ClaimName is the JWT claim the decisions travel in.
const ClaimName = "features"

// GlobalBucket is the claim bucket for decisions that apply in every scope.
const GlobalBucket = "*"

// Feature is an app's feature enum; a generated proto enum satisfies it. A
// feature's name (String) is its identity everywhere outside the binary: the
// claim and the app's decisions table store the name, never the number.
type Feature interface {
	~int32
	String() string
}

// Registry is the set of features an enum defines.
type Registry[F Feature] struct {
	names map[string]bool
}

// NewRegistry builds a Registry from the enum's generated name→value map
// (Foo_value). An enum whose only value is zero is valid: the app gates
// nothing yet.
func NewRegistry[F Feature](values map[string]int32) (*Registry[F], error) {
	r := &Registry[F]{names: make(map[string]bool, len(values))}
	for name, v := range values {
		if got := F(v).String(); got != name {
			return nil, fmt.Errorf("features: enum value %d is named %q, but String() says %q", v, name, got)
		}
		if v == 0 {
			// Zero is what an enum field holds when nobody set it, so it
			// must never name a feature: proto style reserves it for
			// *_UNSPECIFIED. Any other name means a real feature got zero.
			if !strings.HasSuffix(name, "_UNSPECIFIED") {
				return nil, fmt.Errorf("features: enum zero value is %q, want *_UNSPECIFIED", name)
			}
			continue
		}
		r.names[name] = true
	}
	return r, nil
}

// Known reports whether f is a feature of the enum (zero is not).
func (r *Registry[F]) Known(f F) bool { return r.names[f.String()] }

// AssertKnown fails when stored names a feature the enum doesn't define — a
// typo'd row, or one left behind by a deleted enum value — so it red-lights
// boot instead of surfacing later as a silently dark feature. stored is
// typically `select distinct feature from feature_access`.
func (r *Registry[F]) AssertKnown(stored []string) error {
	var unknown []string
	for _, name := range stored {
		if !r.names[name] {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		slices.Sort(unknown)
		return fmt.Errorf("features: stored feature names the enum doesn't define: %v", slices.Compact(unknown))
	}
	return nil
}

// Decisions is the "features" claim: scope (or GlobalBucket) → feature name →
// explicit decision.
type Decisions map[string]map[string]bool

// Embed writes d into mc as the ClaimName claim, replacing any earlier one.
func (d Decisions) Embed(mc *authjwt.ClaimsSet) {
	if mc.Extra == nil {
		mc.Extra = map[string]any{}
	}
	mc.Extra[ClaimName] = d
}

// FromClaims converts the ClaimName claim of verified claims
// (authjwt.Claims.Raw) to Decisions. A token without the claim has none. The
// app signed the claim, so any other shape is an error, not something to
// work around.
func FromClaims(raw map[string]any) (Decisions, error) {
	b, err := json.Marshal(raw[ClaimName])
	if err != nil {
		return nil, fmt.Errorf("features: %w", err)
	}
	var d Decisions
	if err := json.Unmarshal(b, &d); err != nil {
		return nil, fmt.Errorf("features: malformed %q claim: %w", ClaimName, err)
	}
	return d, nil
}

// Enabled reports whether f is on in scope: the scope's decision, else the
// global one, else off. An empty scope or GlobalBucket names no tenant and is
// off, so a request can't pick up global grants by naming "*".
func (d Decisions) Enabled(f fmt.Stringer, scope string) bool {
	if scope == "" || scope == GlobalBucket {
		return false
	}
	if on, ok := d[scope][f.String()]; ok {
		return on
	}
	return d[GlobalBucket][f.String()]
}
