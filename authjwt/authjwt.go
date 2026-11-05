// Package authjwt is a reference HS256 bearer-token verifier — the shape
// Supabase, GoTrue and many gateways issue. Call Verify from your transport's
// auth interceptor and pass the resulting *Claims to gearbox as the Principal.
//
// It is intentionally minimal. For RS256/ES256, JWKS rotation, session cookies,
// or API keys, mint your own Principal in your interceptor.
package authjwt

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/mathis-sperlich/gearbox"
)

// Claims is the principal this package produces, threaded to the TxRunner and Authorize.
type Claims struct {
	// Subject is the token's `sub` claim — the user/identity ID.
	Subject string
	// Roles come from the configured roles claim (default "roles"): a JSON string
	// array or a single string.
	Roles []string
	// Raw is the full claim set, so a host TxRunner can forward it to its tenancy
	// layer (e.g. request.jwt.claims for RLS).
	Raw map[string]any
}

// Verifier validates HS256 bearer tokens.
type Verifier struct {
	secret     []byte
	rolesClaim string
	allowNoExp bool
}

// Option configures a Verifier.
type Option func(*Verifier)

// WithRolesClaim sets the claim name roles are read from (default "roles").
func WithRolesClaim(name string) Option {
	return func(v *Verifier) { v.rolesClaim = name }
}

// AllowMissingExpiration relaxes the default requirement that tokens carry an
// `exp` claim. By default exp-less tokens are rejected (a leaked one is valid
// forever); use this only if your issuer deliberately mints them.
func AllowMissingExpiration() Option {
	return func(v *Verifier) { v.allowNoExp = true }
}

// NewVerifier builds a Verifier from the HMAC signing secret.
func NewVerifier(secret string, opts ...Option) (*Verifier, error) {
	if strings.TrimSpace(secret) == "" {
		return nil, errors.New("authjwt: empty signing secret")
	}
	v := &Verifier{secret: []byte(secret), rolesClaim: "roles"}
	for _, o := range opts {
		o(v)
	}
	return v, nil
}

// Verify parses and validates a token string, returning its Claims.
//
// The token must be a compact HS256 JWS signed with the Verifier's secret
// (any other alg, including "none", is refused; the signature is compared in
// constant time). `exp` must lie in the future (required unless
// AllowMissingExpiration), `nbf`, when present, in the past, and `sub` must
// be a non-empty string.
func (v *Verifier) Verify(token string) (Claims, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("authjwt: malformed token")
	}
	var h header
	if err := decodeSegment(parts[0], &h); err != nil {
		return Claims{}, err
	}
	if h.Alg != "HS256" {
		return Claims{}, fmt.Errorf("authjwt: signing method %q is not HS256", h.Alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil || !hmac.Equal(sig, v.sign(parts[0]+"."+parts[1])) {
		return Claims{}, errors.New("authjwt: invalid signature")
	}
	var reg registered
	if err := decodeSegment(parts[1], &reg); err != nil {
		return Claims{}, err
	}
	now := time.Now()
	switch {
	case reg.Exp == nil && !v.allowNoExp:
		return Claims{}, errors.New("authjwt: token has no exp claim")
	case reg.Exp != nil && !now.Before(time.Unix(int64(*reg.Exp), 0)):
		return Claims{}, errors.New("authjwt: token is expired")
	case reg.Nbf != nil && now.Before(time.Unix(int64(*reg.Nbf), 0)):
		return Claims{}, errors.New("authjwt: token is not valid yet")
	case reg.Sub == "":
		return Claims{}, errors.New("authjwt: token has no sub claim")
	}
	c := Claims{Subject: reg.Sub}
	if err := decodeSegment(parts[1], &c.Raw); err != nil {
		return Claims{}, err
	}
	c.Roles = rolesFrom(c.Raw[v.rolesClaim])
	return c, nil
}

// header is the JOSE header of the tokens this package signs and accepts.
type header struct {
	Alg string `json:"alg"`
}

// registered holds the claims Verify checks. Every claim, these included,
// also lands in Claims.Raw.
type registered struct {
	Sub string   `json:"sub"`
	Exp *float64 `json:"exp"`
	Nbf *float64 `json:"nbf"`
}

// sign returns the HS256 signature of a JWS signing input.
func (v *Verifier) sign(signingInput string) []byte {
	mac := hmac.New(sha256.New, v.secret)
	mac.Write([]byte(signingInput))
	return mac.Sum(nil)
}

func decodeSegment(seg string, into any) error {
	b, err := base64.RawURLEncoding.DecodeString(seg)
	if err == nil {
		err = json.Unmarshal(b, into)
	}
	if err != nil {
		return fmt.Errorf("authjwt: malformed token: %w", err)
	}
	return nil
}

// VerifyBearer verifies an "Authorization" header value ("Bearer <token>"),
// yielding *Claims for use as the gearbox Principal. A missing/invalid token
// becomes gearbox.ErrUnauthenticated.
func (v *Verifier) VerifyBearer(header string) (*Claims, error) {
	if !strings.HasPrefix(header, "Bearer ") {
		return nil, fmt.Errorf("%w: missing bearer token", gearbox.ErrUnauthenticated)
	}
	claims, err := v.Verify(strings.TrimSpace(strings.TrimPrefix(header, "Bearer ")))
	if err != nil {
		return nil, errors.Join(gearbox.ErrUnauthenticated, err)
	}
	return &claims, nil
}

// RolesOf reads roles from a *Claims principal, for an Authorize func to check.
// Non-*Claims principals yield no roles.
func RolesOf(p gearbox.Principal) []string {
	if c, ok := p.(*Claims); ok {
		return c.Roles
	}
	return nil
}

func rolesFrom(v any) []string {
	switch t := v.(type) {
	case string:
		if t == "" {
			return nil
		}
		return []string{t}
	case []any:
		out := make([]string, 0, len(t))
		for _, e := range t {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return t
	default:
		return nil
	}
}
