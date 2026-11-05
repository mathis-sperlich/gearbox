package authjwt_test

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/mathis-sperlich/gearbox/authjwt"
)

func TestSign_RoundTripsThroughVerify(t *testing.T) {
	// Given a verifier and the claims of a signed-in editor with app extras
	v := newVerifier(t)
	now := time.Now().Truncate(time.Second)
	signedInEditor := authjwt.ClaimsSet{
		Subject:  "user-1",
		Roles:    []string{"editor"},
		Issuer:   "gearbox",
		Audience: "authenticated",
		Extra:    map[string]any{"email": "a@b.c", "role": "authenticated"},
	}
	// When the claims are signed and verified again
	token, expiresAt, err := v.Sign(signedInEditor, time.Hour, now)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	claims, err := v.Verify(token)
	// Then every claim survives the round trip and the expiry is now+ttl
	if err != nil {
		t.Fatalf("signed token failed Verify: %v", err)
	}
	if want := now.Add(time.Hour); !expiresAt.Equal(want) {
		t.Fatalf("expiresAt = %v, want %v", expiresAt, want)
	}
	if claims.Subject != "user-1" || len(claims.Roles) != 1 || claims.Roles[0] != "editor" {
		t.Fatalf("claims = %+v", claims)
	}
	if claims.Raw["iss"] != "gearbox" || claims.Raw["aud"] != "authenticated" || claims.Raw["email"] != "a@b.c" || claims.Raw["role"] != "authenticated" {
		t.Fatalf("raw claims = %v", claims.Raw)
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
	token, _, err := issuer.Sign(authjwt.ClaimsSet{Subject: "user-1"}, time.Hour, time.Now())
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

func TestSign_VerifyOnlyEd25519VerifierCannotSign(t *testing.T) {
	// Given a verifier that holds only an Ed25519 public key
	publicKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	verifyOnly, err := authjwt.NewEd25519Verifier(publicKey)
	if err != nil {
		t.Fatalf("NewEd25519Verifier: %v", err)
	}
	// When it is asked to sign
	_, _, err = verifyOnly.Sign(authjwt.ClaimsSet{Subject: "user-1"}, time.Hour, time.Now())
	// Then it refuses
	if err == nil {
		t.Fatal("a verify-only verifier signed a token")
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
	ed25519Token, _, err := ed25519Verifier.Sign(authjwt.ClaimsSet{Subject: "u"}, time.Hour, time.Now())
	if err != nil {
		t.Fatalf("Sign Ed25519: %v", err)
	}
	hs256Token, _, err := hs256Verifier.Sign(authjwt.ClaimsSet{Subject: "u"}, time.Hour, time.Now())
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
	token, _, err := v.Sign(legacyIssuer, time.Hour, time.Now())
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	claims, err := v.Verify(token)
	// Then the extra iss is kept
	if err != nil || claims.Raw["iss"] != "legacy" {
		t.Fatalf("iss = %v err = %v", claims.Raw["iss"], err)
	}
}

func TestSign_TokenFromOtherSecretRejected(t *testing.T) {
	// Given a token signed under secret A
	signer, _ := authjwt.NewVerifier("secret-a-secret-a-secret-a-secret-a")
	otherVerifier, _ := authjwt.NewVerifier("secret-b-secret-b-secret-b-secret-b")
	token, _, err := signer.Sign(authjwt.ClaimsSet{Subject: "u"}, time.Hour, time.Now())
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
	// Given a token signed an hour ago with a one-minute ttl
	v := newVerifier(t)
	expiredToken, _, err := v.Sign(authjwt.ClaimsSet{Subject: "u"}, time.Minute, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	// When it is verified
	_, err = v.Verify(expiredToken)
	// Then it is refused
	if err == nil {
		t.Fatal("Verify accepted a signed token past its exp")
	}
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
	}
	v := newVerifier(t)
	for name, bad := range badInputs {
		t.Run(name, func(t *testing.T) {
			// When it is signed
			token, _, err := v.Sign(bad.claims, bad.ttl, time.Now())
			// Then Sign refuses
			if err == nil {
				t.Fatalf("Sign accepted bad input, token %s", token)
			}
		})
	}
}
