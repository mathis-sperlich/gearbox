package authjwt_test

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/mathis-sperlich/gearbox"
	"github.com/mathis-sperlich/gearbox/authjwt"
)

const testSecret = "super-secret-signing-key"

// validExp is an expiry an hour out — tokens need an `exp` by default.
func validExp() int64 { return time.Now().Add(time.Hour).Unix() }

// mintHS256 signs a token with the given claims using HS256 and secret.
func mintHS256(t *testing.T, secret string, claims jwt.MapClaims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	s, err := tok.SignedString([]byte(secret))
	if err != nil {
		t.Fatalf("sign token: %v", err)
	}
	return s
}

func TestAuthJWT_VerifyReturnsSubjectAndRoles(t *testing.T) {
	v, err := authjwt.NewVerifier(testSecret)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := mintHS256(t, testSecret, jwt.MapClaims{
		"sub":   "user-1",
		"roles": []any{"editor", "viewer"},
		"exp":   validExp(),
	})
	claims, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Fatalf("Subject = %q, want user-1", claims.Subject)
	}
	if len(claims.Roles) != 2 || claims.Roles[0] != "editor" || claims.Roles[1] != "viewer" {
		t.Fatalf("Roles = %v, want [editor viewer]", claims.Roles)
	}
}

func TestAuthJWT_WrongSecretFails(t *testing.T) {
	v, err := authjwt.NewVerifier(testSecret)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := mintHS256(t, "a-different-secret", jwt.MapClaims{"sub": "user-1"})
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("Verify accepted a token signed with the wrong secret")
	}
}

func TestAuthJWT_MissingSubFails(t *testing.T) {
	v, err := authjwt.NewVerifier(testSecret)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := mintHS256(t, testSecret, jwt.MapClaims{"roles": []any{"editor"}})
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("Verify accepted a token with no sub claim")
	}
}

func TestAuthJWT_MissingExpRejectedByDefault(t *testing.T) {
	v, err := authjwt.NewVerifier(testSecret)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := mintHS256(t, testSecret, jwt.MapClaims{"sub": "user-1"}) // no exp
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("Verify accepted a token without an exp claim")
	}
}

func TestAuthJWT_MissingExpAllowedWithOption(t *testing.T) {
	v, err := authjwt.NewVerifier(testSecret, authjwt.AllowMissingExpiration())
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := mintHS256(t, testSecret, jwt.MapClaims{"sub": "user-1"}) // no exp
	claims, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("Verify with AllowMissingExpiration: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Fatalf("Subject = %q, want user-1", claims.Subject)
	}
}

func TestAuthJWT_ExpiredTokenRejected(t *testing.T) {
	v, err := authjwt.NewVerifier(testSecret)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := mintHS256(t, testSecret, jwt.MapClaims{
		"sub": "user-1",
		"exp": time.Now().Add(-time.Hour).Unix(), // already expired
	})
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("Verify accepted an expired token")
	}
}

func TestAuthJWT_AlgNoneRejected(t *testing.T) {
	v, err := authjwt.NewVerifier(testSecret)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	// Build an unsigned "alg: none" token explicitly.
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{"sub": "user-1"})
	signed, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none-token: %v", err)
	}
	if _, err := v.Verify(signed); err == nil {
		t.Fatal("Verify accepted an alg=none token")
	}
}

func TestAuthJWT_VerifyBearerNoHeaderUnauthenticated(t *testing.T) {
	v, err := authjwt.NewVerifier(testSecret)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	_, err = v.VerifyBearer("")
	if !errors.Is(err, gearbox.ErrUnauthenticated) {
		t.Fatalf("err = %v, want ErrUnauthenticated", err)
	}
}

func TestAuthJWT_VerifyBearerValidYieldsClaims(t *testing.T) {
	v, err := authjwt.NewVerifier(testSecret)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	tok := mintHS256(t, testSecret, jwt.MapClaims{
		"sub":   "user-7",
		"roles": []any{"admin"},
		"exp":   validExp(),
	})
	claims, err := v.VerifyBearer("Bearer " + tok)
	if err != nil {
		t.Fatalf("VerifyBearer: %v", err)
	}
	if claims.Subject != "user-7" {
		t.Fatalf("Subject = %q, want user-7", claims.Subject)
	}
	roles := authjwt.RolesOf(claims)
	if len(roles) != 1 || roles[0] != "admin" {
		t.Fatalf("RolesOf = %v, want [admin]", roles)
	}
}
