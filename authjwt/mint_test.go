package authjwt_test

import (
	"testing"
	"time"

	"github.com/mathis-sperlich/gearbox/authjwt"
)

func TestMint_RoundTripsThroughVerify(t *testing.T) {
	// Given a verifier and the claims of a signed-in editor with app extras
	v := newVerifier(t)
	now := time.Now().Truncate(time.Second)
	signedInEditor := authjwt.MintClaims{
		Subject:  "user-1",
		Roles:    []string{"editor"},
		Issuer:   "gearbox",
		Audience: "authenticated",
		Extra:    map[string]any{"email": "a@b.c", "role": "authenticated"},
	}
	// When the claims are minted and verified again
	token, expiresAt, err := v.Mint(signedInEditor, time.Hour, now)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	claims, err := v.Verify(token)
	// Then every claim survives the round trip and the expiry is now+ttl
	if err != nil {
		t.Fatalf("minted token failed Verify: %v", err)
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

func TestMint_RolesUseConfiguredClaim(t *testing.T) {
	// Given a verifier reading roles from app_roles
	v := newVerifier(t, authjwt.WithRolesClaim("app_roles"))
	admin := authjwt.MintClaims{Subject: "u", Roles: []string{"admin"}}
	// When an admin token is minted and verified
	token, _, err := v.Mint(admin, time.Minute, time.Now())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	claims, err := v.Verify(token)
	// Then the roles live under app_roles, not roles
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(claims.Roles) != 1 || claims.Roles[0] != "admin" || claims.Raw["roles"] != nil {
		t.Fatalf("roles = %v raw = %v", claims.Roles, claims.Raw)
	}
}

func TestMint_ExtraIssAllowedWithoutIssuer(t *testing.T) {
	// Given claims that set iss through Extra and leave Issuer empty
	v := newVerifier(t)
	legacyIssuer := authjwt.MintClaims{Subject: "u", Extra: map[string]any{"iss": "legacy"}}
	// When they are minted and verified
	token, _, err := v.Mint(legacyIssuer, time.Hour, time.Now())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	claims, err := v.Verify(token)
	// Then the extra iss is kept
	if err != nil || claims.Raw["iss"] != "legacy" {
		t.Fatalf("iss = %v err = %v", claims.Raw["iss"], err)
	}
}

func TestMint_TokenFromOtherSecretRejected(t *testing.T) {
	// Given a token minted under secret A
	minter, _ := authjwt.NewVerifier("secret-a-secret-a")
	otherVerifier, _ := authjwt.NewVerifier("secret-b-secret-b")
	token, _, err := minter.Mint(authjwt.MintClaims{Subject: "u"}, time.Hour, time.Now())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	// When a verifier with secret B checks it
	_, err = otherVerifier.Verify(token)
	// Then it is refused
	if err == nil {
		t.Fatal("token minted with secret A verified under secret B")
	}
}

func TestMint_ExpiredTokenRejected(t *testing.T) {
	// Given a token minted an hour ago with a one-minute ttl
	v := newVerifier(t)
	expiredToken, _, err := v.Mint(authjwt.MintClaims{Subject: "u"}, time.Minute, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	// When it is verified
	_, err = v.Verify(expiredToken)
	// Then it is refused
	if err == nil {
		t.Fatal("Verify accepted a minted token past its exp")
	}
}

func TestMint_RefusesBadInput(t *testing.T) {
	// Given claims or ttls Mint must refuse, reserved extras among them
	type mintInput struct {
		claims authjwt.MintClaims
		ttl    time.Duration
	}
	badInputs := map[string]mintInput{
		"empty subject": {authjwt.MintClaims{}, time.Hour},
		"zero ttl":      {authjwt.MintClaims{Subject: "u"}, 0},
		"extra sub":     {authjwt.MintClaims{Subject: "u", Extra: map[string]any{"sub": "admin"}}, time.Hour},
		"extra exp":     {authjwt.MintClaims{Subject: "u", Extra: map[string]any{"exp": 1 << 40}}, time.Hour},
		"extra iat":     {authjwt.MintClaims{Subject: "u", Extra: map[string]any{"iat": 0}}, time.Hour},
		"extra roles":   {authjwt.MintClaims{Subject: "u", Extra: map[string]any{"roles": []string{"admin"}}}, time.Hour},
		"extra iss":     {authjwt.MintClaims{Subject: "u", Issuer: "a", Extra: map[string]any{"iss": "b"}}, time.Hour},
	}
	v := newVerifier(t)
	for name, bad := range badInputs {
		t.Run(name, func(t *testing.T) {
			// When it is minted
			token, _, err := v.Mint(bad.claims, bad.ttl, time.Now())
			// Then Mint refuses
			if err == nil {
				t.Fatalf("Mint accepted bad input, token %s", token)
			}
		})
	}
}
