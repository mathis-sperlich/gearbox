// Package authjwt signs and verifies the bearer tokens a gearbox backend
// issues: compact JWS JWTs signed with Ed25519 (preferred; alg "Ed25519",
// RFC 9864) or HS256 (deprecated: one shared secret both signs and verifies).
// Verify from your auth interceptor and pass the *Claims to gearbox as the
// Principal.
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

// Claims is the verified token, used as the gearbox Principal.
type Claims struct {
	Subject   string    // `sub`
	Roles     []string  // `roles`
	ExpiresAt time.Time // `exp`; a stream opened with the token ends here
	Raw       []byte    // the claim set as signed, JSON; bound for RLS (see BindClaims)
}

// Verifier checks tokens of one algorithm and key. Only the New* constructors
// build one.
type Verifier interface {
	// Verify checks a token and returns its claims. Every failure wraps
	// gearbox.ErrUnauthenticated.
	Verify(token string) (*Claims, error)
}

// Signer also issues tokens.
type Signer interface {
	Verifier
	// Sign issues a token for c that expires ttl (at most MaxTTL) from now.
	Sign(c ClaimsSet, ttl time.Duration) (token string, expiresAt time.Time, err error)
}

const (
	// MinSecretSize is the shortest HS256 secret accepted (RFC 7518 §3.2).
	MinSecretSize = sha256.Size
	// MaxTokenSize bounds a token in bytes, on both Sign and Verify.
	MaxTokenSize = 8 << 10
)

// NewVerifier builds an HS256 Signer from a secret of at least MinSecretSize bytes.
//
// Deprecated: Use NewEd25519Signer where tokens are issued and
// NewEd25519Verifier where they are only checked.
func NewVerifier(secret string) (Signer, error) {
	if len(secret) < MinSecretSize {
		return nil, fmt.Errorf("authjwt: HS256 secret must be at least %d bytes, got %d", MinSecretSize, len(secret))
	}
	return &verifier{alg: hs256, secret: []byte(secret)}, nil
}

// NewEd25519Signer builds a Signer from an Ed25519 private key.
func NewEd25519Signer(privateKey ed25519.PrivateKey) (Signer, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil, errors.New("authjwt: Ed25519 private key has the wrong size")
	}
	return &verifier{
		alg:        ed25519Alg,
		publicKey:  privateKey.Public().(ed25519.PublicKey),
		privateKey: privateKey,
	}, nil
}

// NewEd25519Verifier builds a Verifier from an Ed25519 public key.
func NewEd25519Verifier(publicKey ed25519.PublicKey) (Verifier, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("authjwt: Ed25519 public key has the wrong size")
	}
	return &verifier{alg: ed25519Alg, publicKey: publicKey}, nil
}

// RolesOf returns the roles of a *Claims principal, none for anything else.
func RolesOf(p gearbox.Principal) []string {
	if c, ok := p.(*Claims); ok {
		return c.Roles
	}
	return nil
}

type verifier struct {
	alg        algorithm
	secret     []byte             // HS256
	publicKey  ed25519.PublicKey  // Ed25519
	privateKey ed25519.PrivateKey // Ed25519, nil when verify-only
}

// algorithm is a JWS "alg" header value.
type algorithm string

const (
	hs256      algorithm = "HS256"
	ed25519Alg algorithm = "Ed25519"
)

const rolesClaim = "roles"

func (v *verifier) Verify(token string) (*Claims, error) {
	c, err := v.verify(token)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", gearbox.ErrUnauthenticated, err)
	}
	return c, nil
}

func (v *verifier) verify(token string) (*Claims, error) {
	if len(token) > MaxTokenSize {
		return nil, fmt.Errorf("authjwt: token exceeds %d bytes", MaxTokenSize)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, errors.New("authjwt: malformed token")
	}
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, fmt.Errorf("authjwt: malformed token: %w", err)
	}
	var h header
	if err := json.Unmarshal(headerJSON, &h); err != nil {
		return nil, fmt.Errorf("authjwt: malformed token: %w", err)
	}
	if h.Alg != v.alg {
		return nil, errors.New("authjwt: unsupported alg")
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("authjwt: malformed token: %w", err)
	}
	if !v.validSignature(parts[0]+"."+parts[1], sig) {
		return nil, errors.New("authjwt: invalid signature")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, fmt.Errorf("authjwt: malformed token: %w", err)
	}
	var reg verifiedClaims
	if err := json.Unmarshal(payload, &reg); err != nil {
		return nil, fmt.Errorf("authjwt: malformed token: %w", err)
	}
	now := time.Now()
	switch {
	case reg.ExpirationTime.IsZero():
		return nil, errors.New("authjwt: token has no exp claim")
	case !now.Before(reg.ExpirationTime.Time):
		return nil, errors.New("authjwt: token is expired")
	case !reg.NotBefore.IsZero() && now.Before(reg.NotBefore.Time):
		return nil, errors.New("authjwt: token is not valid yet")
	case reg.Subject == "":
		return nil, errors.New("authjwt: token has no sub claim")
	}
	return &Claims{Subject: reg.Subject, Roles: reg.Roles, ExpiresAt: reg.ExpirationTime.Time, Raw: payload}, nil
}

type header struct {
	Alg algorithm `json:"alg"`
}

// verifiedClaims are the claims Verify checks. encoding/json/v2 matches names
// case-sensitively and rejects duplicates, so "Roles" or a second "exp" can't
// reach these fields.
type verifiedClaims struct {
	Subject        string      `json:"sub"`
	ExpirationTime numericDate `json:"exp"`
	NotBefore      numericDate `json:"nbf"`
	Roles          []string    `json:"roles"`
}

// numericDate is an RFC 7519 NumericDate; absent or null is the zero time.
// Stricter than the RFC on purpose: only whole non-negative seconds, which
// Sign always writes. That rules out float overflow and keeps every present
// value after 1970, so none collides with the zero time that means absent.
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
