package authjwt_test

import (
	"crypto/ed25519"
	"fmt"
	"strings"
	"testing"
	"testing/synctest"
	"time"

	"github.com/mathis-sperlich/gearbox/authjwt"
)

func TestSign_RoundTripsThroughVerify(t *testing.T) {
	// Given a verifier and the claims of a signed-in editor with app extras
	v := newVerifier(t)
	signedInEditor := authjwt.ClaimsSet{
		Subject:  "user-1",
		Roles:    []string{"editor"},
		Issuer:   "gearbox",
		Audience: "authenticated",
		Extra:    map[string]any{"email": "a@b.c", "role": "authenticated"},
	}
	// When the claims are signed and verified again
	token, expiresAt, err := v.Sign(signedInEditor, time.Hour)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	claims, err := v.Verify(token)
	// Then every claim survives the round trip and the expiry is ttl out
	if err != nil {
		t.Fatalf("signed token failed Verify: %v", err)
	}
	if until := time.Until(expiresAt); until > time.Hour || until < 59*time.Minute {
		t.Fatalf("expiresAt = %v, want about an hour out", expiresAt)
	}
	if claims.Subject != "user-1" || len(claims.Roles) != 1 || claims.Roles[0] != "editor" {
		t.Fatalf("claims = %+v", claims)
	}
	if raw := rawClaims(t, claims); raw["iss"] != "gearbox" || raw["aud"] != "authenticated" || raw["email"] != "a@b.c" || raw["role"] != "authenticated" {
		t.Fatalf("raw claims = %s", claims.Raw)
	}
}

func TestSign_Ed25519RoundTripsThroughPublicKeyVerifier(t *testing.T) {
	// Given an issuer holding an Ed25519 private key, and a service holding only its public key
	publicKey, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	issuer, err := authjwt.NewEd25519Signer(privateKey)
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	service, err := authjwt.NewEd25519Verifier(publicKey)
	if err != nil {
		t.Fatalf("NewEd25519Verifier: %v", err)
	}
	// When the issuer signs a token and the service verifies it
	token, _, err := issuer.Sign(authjwt.ClaimsSet{Subject: "user-1"}, time.Hour)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	claims, err := service.Verify(token)
	// Then the service accepts it
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if claims.Subject != "user-1" {
		t.Fatalf("Subject = %q, want user-1", claims.Subject)
	}
}

func TestSign_AlgorithmsDoNotCrossVerify(t *testing.T) {
	// Given an HS256 verifier and an Ed25519 verifier, each with a token it signed
	_, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	ed25519Verifier, err := authjwt.NewEd25519Signer(privateKey)
	if err != nil {
		t.Fatalf("NewEd25519Signer: %v", err)
	}
	hs256Verifier := newVerifier(t)
	ed25519Token, _, err := ed25519Verifier.Sign(authjwt.ClaimsSet{Subject: "u"}, time.Hour)
	if err != nil {
		t.Fatalf("Sign Ed25519: %v", err)
	}
	hs256Token, _, err := hs256Verifier.Sign(authjwt.ClaimsSet{Subject: "u"}, time.Hour)
	if err != nil {
		t.Fatalf("Sign HS256: %v", err)
	}
	// When each verifies the other's token
	_, hs256Err := hs256Verifier.Verify(ed25519Token)
	_, ed25519Err := ed25519Verifier.Verify(hs256Token)
	// Then both refuse
	if hs256Err == nil || ed25519Err == nil {
		t.Fatalf("cross-algorithm token accepted: hs256 err = %v, ed25519 err = %v", hs256Err, ed25519Err)
	}
}

func TestSign_ExtraIssAllowedWithoutIssuer(t *testing.T) {
	// Given claims that set iss through Extra and leave Issuer empty
	v := newVerifier(t)
	legacyIssuer := authjwt.ClaimsSet{Subject: "u", Extra: map[string]any{"iss": "legacy"}}
	// When they are signed and verified
	token, _, err := v.Sign(legacyIssuer, time.Hour)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	claims, err := v.Verify(token)
	// Then the extra iss is kept
	if err != nil || rawClaims(t, claims)["iss"] != "legacy" {
		t.Fatalf("raw = %s err = %v", claims.Raw, err)
	}
}

func TestSign_TokenFromOtherSecretRejected(t *testing.T) {
	// Given a token signed under secret A
	signer, _ := authjwt.NewVerifier("secret-a-secret-a-secret-a-secret-a")
	otherVerifier, _ := authjwt.NewVerifier("secret-b-secret-b-secret-b-secret-b")
	token, _, err := signer.Sign(authjwt.ClaimsSet{Subject: "u"}, time.Hour)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// When a verifier with secret B checks it
	_, err = otherVerifier.Verify(token)
	// Then it is refused
	if err == nil {
		t.Fatal("token signed with secret A verified under secret B")
	}
}

func TestSign_ExpiredTokenRejected(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		// Given a token with a one-minute ttl, on a clock this test controls
		v := newVerifier(t)
		shortLivedToken, _, err := v.Sign(authjwt.ClaimsSet{Subject: "u"}, time.Minute)
		if err != nil {
			t.Fatalf("Sign: %v", err)
		}
		// When it is verified two minutes later
		time.Sleep(2 * time.Minute)
		_, err = v.Verify(shortLivedToken)
		// Then it is refused
		if err == nil {
			t.Fatal("Verify accepted a signed token past its exp")
		}
	})
}

func TestSign_RefusesBadInput(t *testing.T) {
	// Given claims or ttls Sign must refuse, reserved extras among them
	type signInput struct {
		claims authjwt.ClaimsSet
		ttl    time.Duration
	}
	badInputs := map[string]signInput{
		"empty subject": {authjwt.ClaimsSet{}, time.Hour},
		"zero ttl":      {authjwt.ClaimsSet{Subject: "u"}, 0},
		"ttl over max":  {authjwt.ClaimsSet{Subject: "u"}, authjwt.MaxTTL + time.Second},
		"extra sub":     {authjwt.ClaimsSet{Subject: "u", Extra: map[string]any{"sub": "admin"}}, time.Hour},
		"extra exp":     {authjwt.ClaimsSet{Subject: "u", Extra: map[string]any{"exp": 1 << 40}}, time.Hour},
		"extra iat":     {authjwt.ClaimsSet{Subject: "u", Extra: map[string]any{"iat": 0}}, time.Hour},
		"extra roles":   {authjwt.ClaimsSet{Subject: "u", Extra: map[string]any{"roles": []string{"admin"}}}, time.Hour},
		"extra iss":     {authjwt.ClaimsSet{Subject: "u", Issuer: "a", Extra: map[string]any{"iss": "b"}}, time.Hour},
		"too large":     {authjwt.ClaimsSet{Subject: "u", Extra: map[string]any{"blob": strings.Repeat("x", authjwt.MaxTokenSize)}}, time.Hour},
		"too many":      {authjwt.ClaimsSet{Subject: "u", Extra: tooManyExtras()}, time.Hour},
	}
	v := newVerifier(t)
	for name, bad := range badInputs {
		t.Run(name, func(t *testing.T) {
			// When it is signed
			token, _, err := v.Sign(bad.claims, bad.ttl)
			// Then Sign refuses
			if err == nil {
				t.Fatalf("Sign accepted bad input, token %s", token)
			}
		})
	}
}

// tooManyExtras is one claim over MaxExtraClaims.
func tooManyExtras() map[string]any {
	extras := map[string]any{}
	for i := 0; i <= authjwt.MaxExtraClaims; i++ {
		extras[fmt.Sprintf("claim_%d", i)] = true
	}
	return extras
}
