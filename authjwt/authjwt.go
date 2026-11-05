// Package authjwt signs and verifies the bearer tokens a gearbox backend
// issues: compact JWS (RFC 7515) JWTs (RFC 7519) signed with Ed25519 or HS256.
// Call Verify from your transport's auth interceptor and pass the resulting
// *Claims to gearbox as the Principal.
//
// Prefer Ed25519 (NewEd25519Signer / NewEd25519Verifier): the backend that
// issues tokens holds the private key, and anything that only checks them
// gets the public key, so a leaked verifier cannot forge tokens. Ed25519
// signatures are also deterministic, with no nonce to get wrong. The header
// carries alg "Ed25519", the fully-specified name RFC 9864 introduces in
// place of the deprecated, polymorphic "EdDSA". HS256 (NewVerifier) is
// deprecated: it shares one secret between issuer and verifiers, and stays
// only for existing deployments.
//
// It is intentionally minimal. For RS256/ES256, JWKS rotation, session
// cookies, or API keys, build your own Principal in your interceptor.
package authjwt

import (
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
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

// Verifier validates bearer tokens of exactly one algorithm, and signs them
// when it holds the signing key (an HS256 secret or an Ed25519 private key).
type Verifier struct {
	alg        algorithm
	secret     []byte             // HS256 only
	publicKey  ed25519.PublicKey  // Ed25519 only
	privateKey ed25519.PrivateKey // Ed25519 only; nil for a verify-only Verifier
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
// forever); use this only if your issuer deliberately issues them.
func AllowMissingExpiration() Option {
	return func(v *Verifier) { v.allowNoExp = true }
}

// NewVerifier builds an HS256 Verifier from the HMAC signing secret. It both
// signs and verifies, so every service that checks tokens also holds the key
// that forges them.
//
// Deprecated: Use NewEd25519Signer in the service that issues tokens and
// NewEd25519Verifier, with the matching public key, wherever tokens are only
// checked. NewVerifier stays for existing HS256 deployments.
func NewVerifier(secret string, opts ...Option) (*Verifier, error) {
	if strings.TrimSpace(secret) == "" {
		return nil, errors.New("authjwt: empty signing secret")
	}
	return newVerifier(&Verifier{alg: hs256, secret: []byte(secret)}, opts), nil
}

// NewEd25519Signer builds a Verifier that signs and verifies Ed25519 tokens
// with privateKey. Use it in the backend that issues tokens.
func NewEd25519Signer(privateKey ed25519.PrivateKey, opts ...Option) (*Verifier, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("authjwt: Ed25519 private key has the wrong size")
	}
	v := &Verifier{
		alg:        ed25519Alg,
		publicKey:  privateKey.Public().(ed25519.PublicKey),
		privateKey: privateKey,
	}
	return newVerifier(v, opts), nil
}

// NewEd25519Verifier builds a verify-only Verifier for Ed25519 tokens signed
// with the private key belonging to publicKey. Sign refuses on it.
func NewEd25519Verifier(publicKey ed25519.PublicKey, opts ...Option) (*Verifier, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("authjwt: Ed25519 public key has the wrong size")
	}
	return newVerifier(&Verifier{alg: ed25519Alg, publicKey: publicKey}, opts), nil
}

func newVerifier(v *Verifier, opts []Option) *Verifier {
	v.rolesClaim = "roles"
	for _, o := range opts {
		o(v)
	}
	return v
}

// Verify parses and validates a token string, returning its Claims.
//
// The token must be a compact JWS signed with the Verifier's algorithm and
// key. Any other alg, including "none", is refused, so an HS256 token never
// passes an Ed25519 Verifier or the other way round; HS256 signatures are
// compared in constant time. `exp` must lie in the future (required unless
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
	if h.Alg != v.alg {
		return Claims{}, fmt.Errorf("authjwt: signing method %q, want %q", h.Alg, v.alg)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, fmt.Errorf("authjwt: malformed token: %w", err)
	}
	if !v.validSignature(parts[0]+"."+parts[1], sig) {
		return Claims{}, errors.New("authjwt: invalid signature")
	}
	var reg registeredClaims
	if err := decodeSegment(parts[1], &reg); err != nil {
		return Claims{}, err
	}
	now := time.Now()
	switch {
	case reg.ExpirationTime.IsZero() && !v.allowNoExp:
		return Claims{}, errors.New("authjwt: token has no exp claim")
	case !reg.ExpirationTime.IsZero() && !now.Before(reg.ExpirationTime.Time):
		return Claims{}, errors.New("authjwt: token is expired")
	case !reg.NotBefore.IsZero() && now.Before(reg.NotBefore.Time):
		return Claims{}, errors.New("authjwt: token is not valid yet")
	case reg.Subject == "":
		return Claims{}, errors.New("authjwt: token has no sub claim")
	}
	c := Claims{Subject: reg.Subject}
	if err := decodeSegment(parts[1], &c.Raw); err != nil {
		return Claims{}, err
	}
	c.Roles = rolesFrom(c.Raw[v.rolesClaim])
	return c, nil
}

// header is the JOSE header of the tokens this package signs and accepts.
type header struct {
	Alg algorithm `json:"alg"`
}

// algorithm is a JWS "alg" header value (RFC 7518 §3.1).
type algorithm string

// The algorithms this package signs with and accepts.
const (
	hs256      algorithm = "HS256"
	ed25519Alg algorithm = "Ed25519" // RFC 9864
)

// registeredClaims holds the RFC 7519 §4.1 Registered Claims Verify checks.
// Every claim, these included, also lands in Claims.Raw.
type registeredClaims struct {
	Subject        string      `json:"sub"`
	ExpirationTime numericDate `json:"exp"`
	NotBefore      numericDate `json:"nbf"`
}

// numericDate is an RFC 7519 NumericDate: seconds since the Unix epoch.
// An absent or null claim leaves the zero time.Time.
//
// Deliberately stricter than RFC 7519, which allows any JSON number
// (fractions, exponents, negatives): Verify only accepts tokens this package
// signed, and Sign always writes whole non-negative seconds. Parsing digits
// only rules out float overflow and keeps every parsed value at or after
// 1970, so a present claim can never collide with the zero time that means
// "absent".
type numericDate struct{ time.Time }

func (d *numericDate) UnmarshalJSON(b []byte) error {
	if string(b) == "null" {
		return nil
	}
	seconds, err := strconv.ParseUint(string(b), 10, 63)
	if err != nil {
		return fmt.Errorf("authjwt: NumericDate must be whole non-negative seconds: %w", err)
	}
	d.Time = time.Unix(int64(seconds), 0)
	return nil
}

// signature returns the signature of a JWS signing input. The caller makes
// sure the Verifier holds a signing key.
func (v *Verifier) signature(signingInput string) []byte {
	if v.alg == ed25519Alg {
		return ed25519.Sign(v.privateKey, []byte(signingInput))
	}
	mac := hmac.New(sha256.New, v.secret)
	mac.Write([]byte(signingInput))
	return mac.Sum(nil)
}

func (v *Verifier) validSignature(signingInput string, sig []byte) bool {
	if v.alg == ed25519Alg {
		return ed25519.Verify(v.publicKey, []byte(signingInput), sig)
	}
	return hmac.Equal(sig, v.signature(signingInput))
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
