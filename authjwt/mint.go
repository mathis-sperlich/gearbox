package authjwt

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"time"
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

// encodedHeader is the JOSE header of every minted token.
var encodedHeader = base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"HS256","typ":"JWT"}`))

// Mint signs an HS256 token for c with the Verifier's secret, valid from now
// for ttl. It returns the token and its expiry. The token always carries
// `exp`, so the default Verifier accepts it until it expires and rejects it
// after.
func (v *Verifier) Mint(c MintClaims, ttl time.Duration, now time.Time) (token string, expiresAt time.Time, err error) {
	if ttl <= 0 {
		return "", time.Time{}, errors.New("authjwt: mint: ttl must be positive")
	}
	expiresAt = now.Add(ttl)
	claims, err := v.claimSet(c, now, expiresAt)
	if err != nil {
		return "", time.Time{}, err
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("authjwt: mint: %w", err)
	}
	signingInput := encodedHeader + "." + base64.RawURLEncoding.EncodeToString(payload)
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(v.sign(signingInput)), expiresAt, nil
}

// claimSet converts c into the JSON claim set of a token issued at iat and
// expiring at exp. Extra goes in first and the claims Mint owns last, so an
// extra can never overwrite them; a reserved key in Extra is still an error.
func (v *Verifier) claimSet(c MintClaims, iat, exp time.Time) (map[string]any, error) {
	if c.Subject == "" {
		return nil, errors.New("authjwt: mint: empty subject")
	}
	reserved := map[string]any{"sub": c.Subject, "iat": iat.Unix(), "exp": exp.Unix()}
	if len(c.Roles) > 0 {
		reserved[v.rolesClaim] = c.Roles
	}
	if c.Issuer != "" {
		reserved["iss"] = c.Issuer
	}
	if c.Audience != "" {
		reserved["aud"] = c.Audience
	}
	claims := make(map[string]any, len(c.Extra)+len(reserved))
	for k, val := range c.Extra {
		if _, owned := reserved[k]; owned || k == v.rolesClaim {
			return nil, fmt.Errorf("authjwt: mint: extra claim %q is reserved", k)
		}
		claims[k] = val
	}
	maps.Copy(claims, reserved)
	return claims, nil
}
