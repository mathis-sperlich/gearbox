// Package authjwt is a reference HS256 bearer-token verifier — the shape
// Supabase, GoTrue and many gateways issue. Call Verify from your transport's
// auth interceptor and pass the resulting *Claims to gearbox as the Principal.
//
// It is intentionally minimal. For RS256/ES256, JWKS rotation, session cookies,
// or API keys, mint your own Principal in your interceptor.
package authjwt

import (
	"errors"
	"fmt"
	"strings"

	"github.com/golang-jwt/jwt/v5"
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
func (v *Verifier) Verify(token string) (Claims, error) {
	parserOpts := []jwt.ParserOption{jwt.WithValidMethods([]string{"HS256"})}
	if !v.allowNoExp {
		parserOpts = append(parserOpts, jwt.WithExpirationRequired())
	}
	parsed, err := jwt.Parse(token, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method %v", t.Header["alg"])
		}
		return v.secret, nil
	}, parserOpts...)
	if err != nil {
		return Claims{}, err
	}
	mc, ok := parsed.Claims.(jwt.MapClaims)
	if !ok || !parsed.Valid {
		return Claims{}, errors.New("authjwt: invalid token")
	}
	c := Claims{Raw: mc}
	if sub, ok := mc["sub"].(string); ok {
		c.Subject = sub
	}
	if c.Subject == "" {
		return Claims{}, errors.New("authjwt: token has no sub claim")
	}
	c.Roles = rolesFrom(mc[v.rolesClaim])
	return c, nil
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
