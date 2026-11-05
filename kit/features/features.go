// Package features gates an app's features per tenant scope, keyed by the
// app's own proto feature enum.
//
// The app resolves a user's Decisions once, when it signs their token, and
// Decisions.Embed writes them into the token as the "features" claim, by
// feature name:
//
//	"features": { "<scope>": { "FEATURE_X": true, ... }, "*": { ... } }
//
// A scope is whatever the app tenants by (an organisation id), spelled
// exactly as requests name it; "*" carries the global grants. Only explicit
// decisions appear; anything absent is off.
//
// Checks never touch the database: NewGate reads the claims connectgear's
// AuthInterceptor already verified and holds in memory, so a decision is as
// fresh as the token.
package features

import (
	"encoding/json/v2"
	"fmt"
	"slices"
	"strings"

	"github.com/mathis-sperlich/gearbox/authjwt"
)

// Feature is an app's feature enum; a generated proto enum satisfies it. A
// feature's name (String) is its identity outside the binary: the claim and
// the app's decisions table store the name, never the number.
type Feature interface {
	~int32
	String() string
}

// Grants are explicit decisions: true turns a feature on, false turns it off.
// Anything absent is undecided.
type Grants[F Feature] map[F]bool

// Decisions is what the app resolved for a user at sign-in. A scope's own
// grant beats the global one; no grant at all means off.
type Decisions[F Feature] struct {
	// Global grants apply in every scope; a feature rolled out to everyone
	// is granted here.
	Global Grants[F]
	// ByScope grants apply in one scope, keyed by the id requests name.
	ByScope map[string]Grants[F]
}

// Enabled reports whether f is on in scope. An empty scope or "*" names no
// tenant and is off, so a request can't reach the global grants by naming "*".
func (d Decisions[F]) Enabled(f F, scope string) bool {
	if scope == "" || scope == globalScope {
		return false
	}
	if on, ok := d.ByScope[scope][f]; ok {
		return on
	}
	return d.Global[f]
}

// Embed writes d into c as the "features" claim, replacing any earlier one.
func (d Decisions[F]) Embed(c *authjwt.ClaimsSet) {
	if c.Extra == nil {
		c.Extra = map[string]any{}
	}
	c.Extra[claimName] = d.claim()
}

// The wire form of Decisions: the "features" claim maps a scope, or "*" for
// the global grants, to feature name → decision.
const (
	claimName   = "features"
	globalScope = "*"
)

type claim map[string]map[string]bool

func (d Decisions[F]) claim() claim {
	wire := make(claim, len(d.ByScope)+1)
	if len(d.Global) > 0 {
		wire[globalScope] = d.Global.byName()
	}
	for scope, grants := range d.ByScope {
		wire[scope] = grants.byName()
	}
	return wire
}

func (g Grants[F]) byName() map[string]bool {
	named := make(map[string]bool, len(g))
	for f, on := range g {
		named[f.String()] = on
	}
	return named
}

// enum maps feature names back to the app's enum values. It is built from
// the enum's generated name→value map (Foo_value) and excludes zero.
type enum[F Feature] map[string]F

func newEnum[F Feature](values map[string]int32) (enum[F], error) {
	e := make(enum[F], len(values))
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
		e[name] = F(v)
	}
	return e, nil
}

// decisionsOf reads the "features" claim out of a verified claim set. A token
// without the claim has no decisions; the app signed the claim, so any other
// shape is an error. A name the enum no longer defines is dropped: the
// feature is gone, so it is off.
func (e enum[F]) decisionsOf(raw []byte) (Decisions[F], error) {
	var claims struct {
		Features claim `json:"features"` // claimName
	}
	if err := json.Unmarshal(raw, &claims); err != nil {
		return Decisions[F]{}, fmt.Errorf("features: malformed %q claim: %w", claimName, err)
	}
	d := Decisions[F]{ByScope: make(map[string]Grants[F], len(claims.Features))}
	for scope, named := range claims.Features {
		if scope == globalScope {
			d.Global = e.grants(named)
		} else {
			d.ByScope[scope] = e.grants(named)
		}
	}
	return d, nil
}

func (e enum[F]) grants(named map[string]bool) Grants[F] {
	g := make(Grants[F], len(named))
	for name, on := range named {
		if f, known := e[name]; known {
			g[f] = on
		}
	}
	return g
}

// AssertKnown fails when stored names a feature the enum (its generated
// name→value map, Foo_value) doesn't define: a typo'd row, or one left behind
// by a deleted enum value. Run it at boot with
// `select distinct feature from feature_access`.
func AssertKnown[F Feature](values map[string]int32, stored []string) error {
	e, err := newEnum[F](values)
	if err != nil {
		return err
	}
	var unknown []string
	for _, name := range stored {
		if _, known := e[name]; !known {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) > 0 {
		slices.Sort(unknown)
		return fmt.Errorf("features: stored feature names the enum doesn't define: %v", slices.Compact(unknown))
	}
	return nil
}
