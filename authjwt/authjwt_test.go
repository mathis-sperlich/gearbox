package authjwt_test

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/mathis-sperlich/gearbox"
	"github.com/mathis-sperlich/gearbox/authjwt"
)

const testSecret = "super-secret-signing-key-of-32-bytes!"

// inAnHour is an expiry an hour out — tokens need an `exp` by default.
func inAnHour() int64 { return time.Now().Add(time.Hour).Unix() }

// signToken builds a compact JWS with the given alg header and claims,
// HMAC-SHA256-signed with secret, independently of the package under test.
func signToken(t *testing.T, alg, secret string, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	return signPayload(t, alg, secret, payload)
}

// signPayload signs an already-encoded claims payload, so a test can hand in
// JSON that no marshaller produces, such as duplicate names.
func signPayload(t *testing.T, alg, secret string, payload []byte) string {
	t.Helper()
	enc := base64.RawURLEncoding
	header, err := json.Marshal(map[string]string{"alg": alg, "typ": "JWT"})
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	signingInput := enc.EncodeToString(header) + "." + enc.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(signingInput))
	return signingInput + "." + enc.EncodeToString(mac.Sum(nil))
}

func newVerifier(t *testing.T) authjwt.Signer {
	t.Helper()
	v, err := authjwt.NewVerifier(testSecret)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}

func TestAuthJWT_VerifyReturnsSubjectAndRoles(t *testing.T) {
	// Given a token for an editor-and-viewer signed with the verifier's secret
	v := newVerifier(t)
	editorToken := signToken(t, "HS256", testSecret, map[string]any{
		"sub": "user-1", "roles": []string{"editor", "viewer"}, "exp": inAnHour(),
	})
	// When it is verified
	claims, err := v.Verify(editorToken)
	// Then subject, roles and the raw claim set come back
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Fatalf("Subject = %q, want user-1", claims.Subject)
	}
	if len(claims.Roles) != 2 || claims.Roles[0] != "editor" || claims.Roles[1] != "viewer" {
		t.Fatalf("Roles = %v, want [editor viewer]", claims.Roles)
	}
	if raw := rawClaims(t, claims); raw["sub"] != "user-1" {
		t.Fatalf("Raw = %s, want sub user-1", claims.Raw)
	}
	if roles := authjwt.RolesOf(claims); len(roles) != 2 {
		t.Fatalf("RolesOf = %v, want the same roles", roles)
	}
}

func TestAuthJWT_RolesClaimIsCaseSensitive(t *testing.T) {
	// Given a token whose only roles-like claim is "Roles", not "roles"
	v := newVerifier(t)
	casedRolesToken := signToken(t, "HS256", testSecret, map[string]any{"sub": "u", "Roles": []string{"admin"}, "exp": inAnHour()})
	// When it is verified
	claims, err := v.Verify(casedRolesToken)
	// Then it carries no roles
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(claims.Roles) != 0 {
		t.Fatalf("roles = %v, want none", claims.Roles)
	}
}

func TestAuthJWT_RejectsInvalidTokens(t *testing.T) {
	// Given tokens that each break one rule Verify enforces
	invalidTokens := map[string]string{
		"wrong secret":    signToken(t, "HS256", "a-different-secret", map[string]any{"sub": "u", "exp": inAnHour()}),
		"alg none":        signToken(t, "none", testSecret, map[string]any{"sub": "u", "exp": inAnHour()}),
		"alg HS512":       signToken(t, "HS512", testSecret, map[string]any{"sub": "u", "exp": inAnHour()}),
		"no sub":          signToken(t, "HS256", testSecret, map[string]any{"roles": []string{"editor"}, "exp": inAnHour()}),
		"duplicate exp":   signPayload(t, "HS256", testSecret, []byte(`{"sub":"u","exp":1,"exp":4102444800}`)),
		"no exp":          signToken(t, "HS256", testSecret, map[string]any{"sub": "u"}),
		"expired":         signToken(t, "HS256", testSecret, map[string]any{"sub": "u", "exp": time.Now().Add(-time.Hour).Unix()}),
		"not before":      signToken(t, "HS256", testSecret, map[string]any{"sub": "u", "exp": inAnHour(), "nbf": inAnHour()}),
		"exp not number":  signToken(t, "HS256", testSecret, map[string]any{"sub": "u", "exp": "tomorrow"}),
		"exp fractional":  signToken(t, "HS256", testSecret, map[string]any{"sub": "u", "exp": float64(inAnHour()) + 0.5}),
		"exp exponent":    signToken(t, "HS256", testSecret, map[string]any{"sub": "u", "exp": json.RawMessage(`9.9e10`)}),
		"exp negative":    signToken(t, "HS256", testSecret, map[string]any{"sub": "u", "exp": -1}),
		"nbf negative":    signToken(t, "HS256", testSecret, map[string]any{"sub": "u", "exp": inAnHour(), "nbf": -1}),
		"unsigned":        "eyJhbGciOiJub25lIn0.eyJzdWIiOiJ1In0.",
		"two segments":    "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1In0",
		"not base64":      "!!!.!!!.!!!",
		"empty":           "",
		"too large":       signToken(t, "HS256", testSecret, map[string]any{"sub": "u", "exp": inAnHour(), "blob": strings.Repeat("x", authjwt.MaxTokenSize)}),
		"tampered claims": tamper(signToken(t, "HS256", testSecret, map[string]any{"sub": "u", "exp": inAnHour()})),
	}
	v := newVerifier(t)
	for name, invalidToken := range invalidTokens {
		t.Run(name, func(t *testing.T) {
			// When it is verified
			_, err := v.Verify(invalidToken)
			// Then the caller is unauthenticated
			if !errors.Is(err, gearbox.ErrUnauthenticated) {
				t.Fatalf("err = %v, want ErrUnauthenticated", err)
			}
		})
	}
}

func TestAuthJWT_TellsUndecodableSignatureFromWrongOne(t *testing.T) {
	// Given a token signed with another secret, and one whose signature is not base64url
	v := newVerifier(t)
	wronglySigned := signToken(t, "HS256", "a-different-secret", map[string]any{"sub": "u", "exp": inAnHour()})
	signed := signToken(t, "HS256", testSecret, map[string]any{"sub": "u", "exp": inAnHour()})
	undecodableSignature := signed[:strings.LastIndex(signed, ".")+1] + "!!!"
	// When both are verified
	_, wrongErr := v.Verify(wronglySigned)
	_, undecodableErr := v.Verify(undecodableSignature)
	// Then the first is an invalid signature and the second a malformed token
	if wrongErr == nil || !strings.Contains(wrongErr.Error(), "invalid signature") {
		t.Fatalf("wrongly signed: err = %v, want invalid signature", wrongErr)
	}
	if undecodableErr == nil || !strings.Contains(undecodableErr.Error(), "malformed token") {
		t.Fatalf("undecodable signature: err = %v, want malformed token", undecodableErr)
	}
}

// tamper swaps a token's claims for an admin's, keeping the original signature.
func tamper(token string) string {
	parts := strings.Split(token, ".")
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"admin","exp":99999999999}`))
	return strings.Join(parts, ".")
}

func TestAuthJWT_RejectsShortSecret(t *testing.T) {
	// Given an HS256 secret one byte under MinSecretSize
	shortSecret := strings.Repeat("x", authjwt.MinSecretSize-1)
	// When a verifier is built from it
	_, err := authjwt.NewVerifier(shortSecret)
	// Then the constructor refuses
	if err == nil {
		t.Fatalf("NewVerifier accepted a %d-byte secret", len(shortSecret))
	}
}

// rawClaims decodes the signed claim set Verify kept for RLS.
func rawClaims(t *testing.T, c *authjwt.Claims) map[string]any {
	t.Helper()
	var raw map[string]any
	if err := json.Unmarshal(c.Raw, &raw); err != nil {
		t.Fatalf("Raw is not a JSON object: %v", err)
	}
	return raw
}
