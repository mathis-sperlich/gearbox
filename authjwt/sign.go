package authjwt

import (
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"time"
)

// ClaimsSet is what Sign puts in a token.
type ClaimsSet struct {
	Subject  string         // `sub`, required
	Roles    []string       // `roles`, omitted when empty
	Issuer   string         // `iss`, omitted when empty
	Audience string         // `aud`, omitted when empty
	Extra    map[string]any // app claims, at most MaxExtraClaims; may not repeat the above, iat or exp
}

const (
	// MaxTTL is the longest token lifetime. A bearer token can't be revoked,
	// so a leaked one must stop working soon; sign a fresh one to stay in.
	MaxTTL = time.Hour
	// MaxExtraClaims bounds ClaimsSet.Extra.
	MaxExtraClaims = 16
)

func (v *verifier) Sign(c ClaimsSet, ttl time.Duration) (token string, expiresAt time.Time, err error) {
	switch {
	case ttl <= 0:
		return "", time.Time{}, errors.New("authjwt: sign: ttl must be positive")
	case ttl > MaxTTL:
		return "", time.Time{}, fmt.Errorf("authjwt: sign: ttl %v exceeds MaxTTL %v", ttl, MaxTTL)
	}
	now := time.Now()
	expiresAt = now.Add(ttl)
	claims, err := claimSet(c, now, expiresAt)
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
	token = signingInput + "." + base64.RawURLEncoding.EncodeToString(sig)
	if len(token) > MaxTokenSize {
		return "", time.Time{}, fmt.Errorf("authjwt: sign: token exceeds %d bytes", MaxTokenSize)
	}
	return token, expiresAt, nil
}

// claimSet merges c into one claim set: Extra first, the claims Sign owns
// last so an extra can never overwrite them.
func claimSet(c ClaimsSet, iat, exp time.Time) (map[string]any, error) {
	if c.Subject == "" {
		return nil, errors.New("authjwt: sign: empty subject")
	}
	if len(c.Extra) > MaxExtraClaims {
		return nil, fmt.Errorf("authjwt: sign: %d extra claims, at most %d allowed", len(c.Extra), MaxExtraClaims)
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
