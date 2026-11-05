// Package features gates an app's features per tenant scope, keyed by the
// app's own feature enum (a generated proto enum, or any ~int32 type with a
// String method and a name→value map).
//
// Decisions are resolved once, when a token is minted: Embed asks the app's
// Resolver for the principal's explicit decisions and writes them into the
// token as the "features" claim. Checks afterwards are map lookups on the
// verified claims — no DB reads, no cache; staleness is bounded by the token
// TTL.
//
// Claim shape:
//
//	"features": { "<scope>": { "FEATURE_X": true, ... }, "*": { ... } }
//
// A scope is whatever the app tenants by (an organisation id, a workspace
// slug); "*" holds decisions that apply everywhere. Only explicit decisions
// appear; anything absent resolves OFF — dark by default.
//
// Gate turns a procedure→feature map into a Connect interceptor that fails
// closed, Has answers "is f on here?" inside a handler, and AssertKnown
// red-lights boot when the decisions table names a feature the compiled enum
// doesn't know.
package features

import (
	"fmt"
	"maps"
	"sort"
	"strings"
)

// ClaimName is the JWT claim the decisions travel in.
const ClaimName = "features"

// GlobalBucket is the claim bucket for decisions that aren't scoped to one
// tenant. A global grant is how a feature goes GA.
const GlobalBucket = "*"

// Feature is the constraint on an app's feature enum: a generated proto enum
// satisfies it as is.
type Feature interface {
	~int32
	String() string
}

// Registry is the set of known values of a feature enum, by name. The zero
// value (proto's *_UNSPECIFIED) is never a feature.
type Registry[F Feature] struct {
	byName map[string]F
}

// NewRegistry builds a Registry from the enum's name→value map (the generated
// Foo_value). Values must be distinct and named as their String method names
// them; zero is skipped.
func NewRegistry[F Feature](values map[string]int32) (*Registry[F], error) {
	r := &Registry[F]{byName: make(map[string]F, len(values))}
	for name, v := range values {
		if v == 0 {
			continue
		}
		f := F(v)
		if f.String() != name {
			return nil, fmt.Errorf("features: enum value %d is named %q, but String() says %q", v, name, f.String())
		}
		r.byName[name] = f
	}
	if len(r.byName) == 0 {
		return nil, fmt.Errorf("features: enum has no values besides zero")
	}
	return r, nil
}

// Lookup returns the feature named name. ok is false for unknown names and
// for the zero value.
func (r *Registry[F]) Lookup(name string) (f F, ok bool) {
	f, ok = r.byName[name]
	return f, ok
}

// Known reports whether f is a non-zero value of the enum.
func (r *Registry[F]) Known(f F) bool {
	g, ok := r.byName[f.String()]
	return ok && g == f
}

// Names returns every known feature name, sorted.
func (r *Registry[F]) Names() []string {
	out := make([]string, 0, len(r.byName))
	for name := range r.byName {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Unknown returns the names in names the registry doesn't know, sorted and
// deduplicated. The zero value's name counts as unknown.
func (r *Registry[F]) Unknown(names []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, n := range names {
		if _, ok := r.byName[n]; !ok && !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	sort.Strings(out)
	return out
}

// Decisions is the parsed claim: bucket (canonical scope or GlobalBucket) →
// feature name → explicit enabled/disabled decision.
type Decisions map[string]map[string]bool

// FromClaims parses the ClaimName claim out of a verified claim map
// (authjwt.Claims.Raw). Absent or malformed claims, buckets and entries are
// dropped, so they resolve off.
func FromClaims(raw map[string]any) Decisions {
	out := Decisions{}
	switch claim := raw[ClaimName].(type) {
	case map[string]any:
		for bucket, v := range claim {
			switch m := v.(type) {
			case map[string]any:
				decisions := make(map[string]bool, len(m))
				for name, ev := range m {
					if b, ok := ev.(bool); ok {
						decisions[name] = b
					}
				}
				out[bucket] = decisions
			case map[string]bool:
				out[bucket] = cloneBucket(m)
			}
		}
	case map[string]map[string]bool:
		// Not round-tripped through JSON (a claim map built in process).
		for bucket, m := range claim {
			out[bucket] = cloneBucket(m)
		}
	case Decisions:
		for bucket, m := range claim {
			out[bucket] = cloneBucket(m)
		}
	}
	return out
}

func cloneBucket(m map[string]bool) map[string]bool {
	out := make(map[string]bool, len(m))
	maps.Copy(out, m)
	return out
}

// Enabled answers "is the feature named name on in scope?": the scope's
// decision first, then the global bucket, then off. scope must already be
// canonical (see Gate's Canonical); an empty scope or GlobalBucket names no
// tenant and resolves off — falling through would hand junk input every
// global grant.
func (d Decisions) Enabled(name, scope string) bool {
	if scope == "" || scope == GlobalBucket {
		return false
	}
	if v, ok := d[scope][name]; ok {
		return v
	}
	return d.EnabledGlobally(name)
}

// EnabledGlobally answers from the global bucket alone, for an app that
// doesn't tenant.
func (d Decisions) EnabledGlobally(name string) bool {
	return d[GlobalBucket][name]
}

// UUIDScope canonicalises a UUID scope to its lower-case hyphenated form,
// accepting the spellings Postgres and most UUID parsers accept (upper case,
// braces, urn:uuid: prefix, no hyphens). Claim buckets are keyed by the
// canonical form, so without this "ABC…" would miss its tenant's bucket and
// fall through to the global one, lifting a tenant-level denial. Anything
// that isn't a UUID is refused.
func UUIDScope(s string) (string, bool) {
	switch len(s) {
	case 36:
	case 38:
		if s[0] != '{' || s[37] != '}' {
			return "", false
		}
		s = s[1:37]
	case 45:
		if !strings.EqualFold(s[:9], "urn:uuid:") {
			return "", false
		}
		s = s[9:]
	case 32:
		if !isHex(s) {
			return "", false
		}
		s = s[:8] + "-" + s[8:12] + "-" + s[12:16] + "-" + s[16:20] + "-" + s[20:]
	default:
		return "", false
	}
	if s[8] != '-' || s[13] != '-' || s[18] != '-' || s[23] != '-' {
		return "", false
	}
	if !isHex(s[:8] + s[9:13] + s[14:18] + s[19:23] + s[24:]) {
		return "", false
	}
	return strings.ToLower(s), true
}

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !('0' <= c && c <= '9' || 'a' <= c && c <= 'f' || 'A' <= c && c <= 'F') {
			return false
		}
	}
	return true
}
