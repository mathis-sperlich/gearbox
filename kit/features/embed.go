package features

import (
	"context"
	"errors"
	"fmt"

	"github.com/mathis-sperlich/gearbox"
	"github.com/mathis-sperlich/gearbox/authjwt"
)

// Resolver returns the explicit feature decisions for a principal, keyed by
// canonical scope (and GlobalBucket). It is the app's policy: typically a
// query over a feature_access table, joined with the principal's memberships.
type Resolver func(ctx context.Context, p gearbox.Principal) (Decisions, error)

// Embed resolves p's decisions and writes them into mc as the ClaimName
// claim, so the minted token carries them. Names the registry doesn't know
// are dropped (they would gate nothing). An existing ClaimName entry in
// mc.Extra is replaced.
func (r *Registry[F]) Embed(ctx context.Context, resolve Resolver, p gearbox.Principal, mc *authjwt.MintClaims) error {
	if resolve == nil {
		return errors.New("features: nil resolver")
	}
	d, err := resolve(ctx, p)
	if err != nil {
		return fmt.Errorf("features: resolving decisions: %w", err)
	}
	claim := make(map[string]map[string]bool, len(d))
	for bucket, m := range d {
		kept := make(map[string]bool, len(m))
		for name, on := range m {
			if _, ok := r.byName[name]; ok {
				kept[name] = on
			}
		}
		if len(kept) > 0 {
			claim[bucket] = kept
		}
	}
	if mc.Extra == nil {
		mc.Extra = map[string]any{}
	}
	mc.Extra[ClaimName] = claim
	return nil
}
