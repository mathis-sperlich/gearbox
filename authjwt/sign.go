package authjwt

import (
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"time"
)

// ClaimsSet is the JWT Claims Set (RFC 7519 §2) Sign puts in a token.
// Subject and Roles land in the same claims Verify reads them from, so a
// signed token round-trips through the Verifier that signed it.
type ClaimsSet struct {
	// Subject becomes `sub`. Required.
	Subject string
	// Roles become `roles`. Omitted when empty.
	Roles []string
	// Issuer becomes `iss` when set.
	Issuer string
	// Audience becomes `aud` when set.
	Audience string
	// Extra carries app-specific claims (email, a Postgres `role`, a features
	// map, a session id, ...). It may not set a claim Sign owns: sub, iat, exp,
	// roles, and iss/aud when Issuer/Audience are set.
	Extra map[string]any
}

// MaxTTL is the longest lifetime Sign gives a token. It is fixed by design:
// a bearer token can't be revoked before it expires, so a leaked one must
// stop working soon. Keep sessions longer than this by signing a fresh token.
const MaxTTL = time.Hour

func (v *verifier) Sign(c ClaimsSet, ttl time.Duration, now time.Time) (token string, expiresAt time.Time, err error) {
	switch {
	case ttl <= 0:
		return "", time.Time{}, errors.New("authjwt: sign: ttl must be positive")
	case ttl > MaxTTL:
		return "", time.Time{}, fmt.Errorf("authjwt: sign: ttl %v exceeds MaxTTL %v", ttl, MaxTTL)
	}
	expiresAt = now.Add(ttl)
	claims, err := v.claimSet(c, now, expiresAt)
	if err != nil {
		return "", time.Time{}, err
	}
	payload, err := json.Marshal(claims, json.Deterministic(true))
	if err != nil {
		return "", time.Time{}, fmt.Errorf("authjwt: sign: %w", err)
	}
	header, err := json.Marshal(map[string]any{"alg": v.alg, "typ": "JWT"})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("authjwt: sign: %w", err)
	}
	signingInput := base64.RawURLEncoding.EncodeToString(header) + "." + base64.RawURLEncoding.EncodeToString(payload)
	sig, err := v.signature(signingInput)
	if err != nil {
		return "", time.Time{}, err
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(sig), expiresAt, nil
}

// claimSet converts c into the JSON claim set of a token issued at iat and
// expiring at exp. Extra goes in first and the claims Sign owns last, so an
// extra can never overwrite them; a reserved key in Extra is still an error.
func (v *verifier) claimSet(c ClaimsSet, iat, exp time.Time) (map[string]any, error) {
	if c.Subject == "" {
		return nil, errors.New("authjwt: sign: empty subject")
	}
	reserved := map[string]any{"sub": c.Subject, "iat": iat.Unix(), "exp": exp.Unix()}
	if len(c.Roles) > 0 {
		reserved[rolesClaim] = c.Roles
	}
	if c.Issuer != "" {
		reserved["iss"] = c.Issuer
	}
	if c.Audience != "" {
		reserved["aud"] = c.Audience
	}
	claims := make(map[string]any, len(c.Extra)+len(reserved))
	for k, val := range c.Extra {
		if _, owned := reserved[k]; owned || k == rolesClaim {
			return nil, fmt.Errorf("authjwt: sign: extra claim %q is reserved", k)
		}
		claims[k] = val
	}
	maps.Copy(claims, reserved)
	return claims, nil
}
