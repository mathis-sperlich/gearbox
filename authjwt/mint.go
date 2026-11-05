package authjwt

import (
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// MintClaims is the claim set Mint signs. Subject and Roles land in the same
// claims Verify reads them from, so a minted token round-trips through the
// Verifier that minted it.
type MintClaims struct {
	// Subject becomes `sub`. Required.
	Subject string
	// Roles are written under the Verifier's roles claim (default "roles").
	// Omitted when empty.
	Roles []string
	// Issuer becomes `iss` when set.
	Issuer string
	// Audience becomes `aud` when set.
	Audience string
	// Extra carries app-specific claims (email, a Postgres `role`, a features
	// map, a session id, ...). It may not set a claim Mint owns: sub, iat, exp,
	// the roles claim, and iss/aud when Issuer/Audience are set.
	Extra map[string]any
}

// Mint signs an HS256 token for c with the Verifier's secret, valid from now
// for ttl. It returns the token and its expiry. The token always carries
// `exp`, so the default Verifier accepts it until it expires and rejects it
// after.
func (v *Verifier) Mint(c MintClaims, ttl time.Duration, now time.Time) (token string, expiresAt time.Time, err error) {
	if c.Subject == "" {
		return "", time.Time{}, errors.New("authjwt: mint: empty subject")
	}
	if ttl <= 0 {
		return "", time.Time{}, errors.New("authjwt: mint: ttl must be positive")
	}
	expiresAt = now.Add(ttl)
	mc := jwt.MapClaims{
		"sub": c.Subject,
		"iat": now.Unix(),
		"exp": expiresAt.Unix(),
	}
	if len(c.Roles) > 0 {
		mc[v.rolesClaim] = c.Roles
	}
	if c.Issuer != "" {
		mc["iss"] = c.Issuer
	}
	if c.Audience != "" {
		mc["aud"] = c.Audience
	}
	for k, val := range c.Extra {
		if _, owned := mc[k]; owned || k == v.rolesClaim || k == "sub" || k == "iat" || k == "exp" {
			return "", time.Time{}, fmt.Errorf("authjwt: mint: extra claim %q is reserved", k)
		}
		mc[k] = val
	}
	token, err = jwt.NewWithClaims(jwt.SigningMethodHS256, mc).SignedString(v.secret)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("authjwt: mint: %w", err)
	}
	return token, expiresAt, nil
}
