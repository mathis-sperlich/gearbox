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
	"encoding/json/v2"
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
	// Roles is the token's `roles` claim: a JSON string array.
	Roles []string
	// Raw is the full claim set, so a host TxRunner can forward it to its tenancy
	// layer (e.g. request.jwt.claims for RLS).
	Raw map[string]any
}

// Verifier validates bearer tokens of exactly one algorithm, and signs them
// when it holds the signing key (an HS256 secret or an Ed25519 private key).
// Only the New* constructors produce one, so a Verifier is always bound to a
// known algorithm and a key; there is no zero value that could accept a token.
type Verifier interface {
	// Verify parses and validates a token string, returning its Claims.
	//
	// The token must be a compact JWS signed with the Verifier's algorithm
	// and key. Any other alg, including "none", is refused, so an HS256 token
	// never passes an Ed25519 Verifier or the other way round; HS256
	// signatures are compared in constant time. `exp` is required and must
	// lie in the future (a token that never expires is never accepted),
	// `nbf`, when present, in the past, and `sub` must be a non-empty string.
	Verify(token string) (Claims, error)
	// VerifyBearer verifies an "Authorization" header value ("Bearer <token>"),
	// yielding *Claims for use as the gearbox Principal. A missing/invalid
	// token becomes gearbox.ErrUnauthenticated.
	VerifyBearer(header string) (*Claims, error)
	// Sign creates a JWT for c (RFC 7519 §7.1) as a compact JWS (RFC 7515),
	// signed with the Verifier's key and valid from now for ttl, which must
	// be positive and at most MaxTTL. It returns the token, at most
	// MaxTokenSize bytes, and its expiry.
	// The token always carries `exp`, so a Verifier accepts it until
	// it expires and rejects it after. A verify-only Ed25519 Verifier refuses
	// to sign.
	Sign(c ClaimsSet, ttl time.Duration, now time.Time) (token string, expiresAt time.Time, err error)
}

// MinSecretSize is the shortest HS256 secret NewVerifier accepts: the
// HMAC-SHA256 output size, as RFC 7518 §3.2 requires.
const MinSecretSize = sha256.Size

// verifier is the only Verifier implementation.
type verifier struct {
	alg        algorithm
	secret     []byte             // HS256 only
	publicKey  ed25519.PublicKey  // Ed25519 only
	privateKey ed25519.PrivateKey // Ed25519 only; nil for a verify-only Verifier
}

// rolesClaim is the claim Sign writes Roles to; verifiedClaims reads it back.
const rolesClaim = "roles"

// NewVerifier builds an HS256 Verifier from the HMAC signing secret, which
// must be at least MinSecretSize bytes. It both signs and verifies, so every
// service that checks tokens also holds the key that forges them.
//
// Deprecated: Use NewEd25519Signer in the service that issues tokens and
// NewEd25519Verifier, with the matching public key, wherever tokens are only
// checked. NewVerifier stays for existing HS256 deployments.
func NewVerifier(secret string) (Verifier, error) {
	if len(secret) < MinSecretSize {
		return nil, fmt.Errorf("authjwt: HS256 secret must be at least %d bytes, got %d", MinSecretSize, len(secret))
	}
	return &verifier{alg: hs256, secret: []byte(secret)}, nil
}

// NewEd25519Signer builds a Verifier that signs and verifies Ed25519 tokens
// with privateKey. Use it in the backend that issues tokens.
func NewEd25519Signer(privateKey ed25519.PrivateKey) (Verifier, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("authjwt: Ed25519 private key has the wrong size")
	}
	return &verifier{
		alg:        ed25519Alg,
		publicKey:  privateKey.Public().(ed25519.PublicKey),
		privateKey: privateKey,
	}, nil
}

// NewEd25519Verifier builds a verify-only Verifier for Ed25519 tokens signed
// with the private key belonging to publicKey. Sign refuses on it.
func NewEd25519Verifier(publicKey ed25519.PublicKey) (Verifier, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("authjwt: Ed25519 public key has the wrong size")
	}
	return &verifier{alg: ed25519Alg, publicKey: publicKey}, nil
}

// MaxTokenSize is the longest token Sign issues and Verify reads, in bytes.
// A token travels in a request header and its claims are bound into every
// transaction, so it must stay small; 8 KiB is several times a typical JWT.
const MaxTokenSize = 8 << 10

func (v *verifier) Verify(token string) (Claims, error) {
	if len(token) > MaxTokenSize {
		return Claims{}, fmt.Errorf("authjwt: token exceeds %d bytes", MaxTokenSize)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return Claims{}, errors.New("authjwt: malformed token")
	}
	var h header
	if err := decodeSegment(parts[0], &h); err != nil {
		return Claims{}, err
	}
	if h.Alg != v.alg {
		return Claims{}, errors.New("authjwt: unsupported alg")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return Claims{}, fmt.Errorf("authjwt: malformed token: %w", err)
	}
	if !v.validSignature(parts[0]+"."+parts[1], sig) {
		return Claims{}, errors.New("authjwt: invalid signature")
	}
	var reg verifiedClaims
	if err := decodeSegment(parts[1], &reg); err != nil {
		return Claims{}, err
	}
	now := time.Now()
	switch {
	case reg.ExpirationTime.IsZero():
		return Claims{}, errors.New("authjwt: token has no exp claim")
	case !now.Before(reg.ExpirationTime.Time):
		return Claims{}, errors.New("authjwt: token is expired")
	case !reg.NotBefore.IsZero() && now.Before(reg.NotBefore.Time):
		return Claims{}, errors.New("authjwt: token is not valid yet")
	case reg.Subject == "":
		return Claims{}, errors.New("authjwt: token has no sub claim")
	}
	c := Claims{Subject: reg.Subject, Roles: reg.Roles}
	if err := decodeSegment(parts[1], &c.Raw); err != nil {
		return Claims{}, err
	}
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

// verifiedClaims are the claims Verify checks or returns typed: the RFC 7519
// §4.1 Registered Claims it validates plus the roles claim. Every claim, these
// included, also lands in Claims.Raw. Decoded with encoding/json/v2, which
// matches names case-sensitively and rejects duplicate names, so "Roles" or a
// second "exp" can't reach these fields.
type verifiedClaims struct {
	Subject        string      `json:"sub"`
	ExpirationTime numericDate `json:"exp"`
	NotBefore      numericDate `json:"nbf"`
	Roles          []string    `json:"roles"`
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

// signature returns the signature of a JWS signing input, or an error when
// the verifier holds no signing key for its algorithm.
func (v *verifier) signature(signingInput string) ([]byte, error) {
	switch v.alg {
	case ed25519Alg:
		if v.privateKey == nil {
			return nil, errors.New("authjwt: sign: verifier holds no private key")
		}
		return ed25519.Sign(v.privateKey, []byte(signingInput)), nil
	case hs256:
		if len(v.secret) < MinSecretSize {
			return nil, errors.New("authjwt: sign: verifier holds no HS256 secret")
		}
		mac := hmac.New(sha256.New, v.secret)
		mac.Write([]byte(signingInput))
		return mac.Sum(nil), nil
	default:
		return nil, fmt.Errorf("authjwt: sign: unsupported algorithm %q", v.alg)
	}
}

// validSignature reports whether sig signs signingInput under the verifier's
// key. Anything but the two known algorithms is invalid.
func (v *verifier) validSignature(signingInput string, sig []byte) bool {
	switch v.alg {
	case ed25519Alg:
		return len(v.publicKey) == ed25519.PublicKeySize &&
			ed25519.Verify(v.publicKey, []byte(signingInput), sig)
	case hs256:
		want, err := v.signature(signingInput)
		return err == nil && hmac.Equal(sig, want)
	default:
		return false
	}
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

func (v *verifier) VerifyBearer(header string) (*Claims, error) {
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
