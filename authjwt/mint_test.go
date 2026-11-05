package authjwt_test

import (
	"strings"
	"testing"
	"time"

	"github.com/mathis-sperlich/gearbox/authjwt"
)

func TestMint_RoundTripsThroughVerify(t *testing.T) {
	v, err := authjwt.NewVerifier(testSecret)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	now := time.Now().Truncate(time.Second)
	features := map[string]map[string]bool{"org-1": {"FEATURE_X": true}}
	tok, exp, err := v.Mint(authjwt.MintClaims{
		Subject:  "user-1",
		Roles:    []string{"editor"},
		Issuer:   "gearbox",
		Audience: "authenticated",
		Extra:    map[string]any{"email": "a@b.c", "role": "authenticated", "features": features},
	}, time.Hour, now)
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if want := now.Add(time.Hour); !exp.Equal(want) {
		t.Fatalf("expiresAt = %v, want %v", exp, want)
	}
	c, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("minted token failed Verify: %v", err)
	}
	if c.Subject != "user-1" || len(c.Roles) != 1 || c.Roles[0] != "editor" {
		t.Fatalf("claims = %+v", c)
	}
	if c.Raw["iss"] != "gearbox" || c.Raw["aud"] != "authenticated" || c.Raw["email"] != "a@b.c" || c.Raw["role"] != "authenticated" {
		t.Fatalf("raw claims = %v", c.Raw)
	}
	fc, ok := c.Raw["features"].(map[string]any)
	if !ok {
		t.Fatalf("features claim = %T", c.Raw["features"])
	}
	if b, _ := fc["org-1"].(map[string]any); b["FEATURE_X"] != true {
		t.Fatalf("features = %v", fc)
	}
}

func TestMint_RolesUseConfiguredClaim(t *testing.T) {
	v, _ := authjwt.NewVerifier(testSecret, authjwt.WithRolesClaim("app_roles"))
	tok, _, err := v.Mint(authjwt.MintClaims{Subject: "u", Roles: []string{"admin"}}, time.Minute, time.Now())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	c, err := v.Verify(tok)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if len(c.Roles) != 1 || c.Roles[0] != "admin" || c.Raw["roles"] != nil {
		t.Fatalf("roles = %v raw = %v", c.Roles, c.Raw)
	}
}

func TestMint_WrongSecretRejected(t *testing.T) {
	a, _ := authjwt.NewVerifier("secret-a-secret-a")
	b, _ := authjwt.NewVerifier("secret-b-secret-b")
	tok, _, err := a.Mint(authjwt.MintClaims{Subject: "u"}, time.Hour, time.Now())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := b.Verify(tok); err == nil {
		t.Fatal("token minted with secret A verified under secret B")
	}
}

func TestMint_ExpiredTokenRejected(t *testing.T) {
	v, _ := authjwt.NewVerifier(testSecret)
	tok, _, err := v.Mint(authjwt.MintClaims{Subject: "u"}, time.Minute, time.Now().Add(-time.Hour))
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if _, err := v.Verify(tok); err == nil {
		t.Fatal("Verify accepted a minted token past its exp")
	}
}

func TestMint_RefusesBadInput(t *testing.T) {
	v, _ := authjwt.NewVerifier(testSecret)
	now := time.Now()
	cases := map[string]struct {
		c   authjwt.MintClaims
		ttl time.Duration
	}{
		"empty subject": {authjwt.MintClaims{}, time.Hour},
		"zero ttl":      {authjwt.MintClaims{Subject: "u"}, 0},
		"extra sub":     {authjwt.MintClaims{Subject: "u", Extra: map[string]any{"sub": "admin"}}, time.Hour},
		"extra exp":     {authjwt.MintClaims{Subject: "u", Extra: map[string]any{"exp": 1 << 40}}, time.Hour},
		"extra iat":     {authjwt.MintClaims{Subject: "u", Extra: map[string]any{"iat": 0}}, time.Hour},
		"extra roles":   {authjwt.MintClaims{Subject: "u", Extra: map[string]any{"roles": []string{"admin"}}}, time.Hour},
		"extra iss":     {authjwt.MintClaims{Subject: "u", Issuer: "a", Extra: map[string]any{"iss": "b"}}, time.Hour},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if tok, _, err := v.Mint(tc.c, tc.ttl, now); err == nil {
				t.Fatalf("Mint accepted bad input, token %s", tok)
			}
		})
	}
}

func TestMint_ExtraIssAllowedWithoutIssuer(t *testing.T) {
	v, _ := authjwt.NewVerifier(testSecret)
	tok, _, err := v.Mint(authjwt.MintClaims{Subject: "u", Extra: map[string]any{"iss": "legacy"}}, time.Hour, time.Now())
	if err != nil {
		t.Fatalf("Mint: %v", err)
	}
	if strings.Count(tok, ".") != 2 {
		t.Fatalf("not a JWS: %s", tok)
	}
	c, err := v.Verify(tok)
	if err != nil || c.Raw["iss"] != "legacy" {
		t.Fatalf("iss = %v err = %v", c.Raw["iss"], err)
	}
}
