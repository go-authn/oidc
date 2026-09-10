package oidc_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/oidc"
)

// A token, signed by somebody else, verified here.
func TestATokenFromTheIssuer(t *testing.T) {
	p := newProvider(t)
	v := verifier(t, p, oidc.Config{})
	raw := sign(t, p.rsaPEM(t), "RS256", claims(p, map[string]any{
		"preferred_username": "dora",
		"email":              "dora@example.org",
		"email_verified":     true,
		"groups":             []string{"engineers", "oncall"},
	}), map[string]any{"kid": "rsa-1"})

	tok, err := v.Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("a token from the issuer was refused: %v", err)
	}
	if tok.Subject() != "user-1" {
		t.Errorf("Subject() = %q", tok.Subject())
	}
	if tok.Username() != "dora" {
		t.Errorf("Username() = %q", tok.Username())
	}
	if tok.Email() != "dora@example.org" || !tok.EmailVerified() {
		t.Errorf("Email() = %q, verified = %v", tok.Email(), tok.EmailVerified())
	}
	if got := strings.Join(tok.Groups(), ","); got != "engineers,oncall" {
		t.Errorf("Groups() = %q", got)
	}
	if exp, ok := tok.Expiry(); !ok || exp.Before(time.Now()) {
		t.Errorf("Expiry() = %v, %v", exp, ok)
	}
	// A bearer token arrives with the header's spelling around it.
	if _, err := v.Verify(context.Background(), "  "+raw+"\n"); err != nil {
		t.Errorf("a token with spaces around it was refused: %v", err)
	}
}

// Every signature algorithm a provider might use, and every one it might not.
func TestTheAlgorithmsThisAccepts(t *testing.T) {
	p := newProvider(t)
	v := verifier(t, p, oidc.Config{})
	for _, tc := range []struct{ alg, key, kid string }{
		{"RS256", p.rsaPEM(t), "rsa-1"},
		{"RS512", p.rsaPEM(t), "rsa-1"},
		{"PS256", p.rsaPEM(t), "rsa-1"},
		{"ES256", p.ecPEM(t), "ec-1"},
	} {
		raw := sign(t, tc.key, tc.alg, claims(p, nil), map[string]any{"kid": tc.kid})
		if _, err := v.Verify(context.Background(), raw); err != nil {
			t.Errorf("%s was refused: %v", tc.alg, err)
		}
	}
}

// ⛔ The refusals. Each is a token that is valid JOSE and must not be accepted.
func TestTokensThatMustBeRefused(t *testing.T) {
	p := newProvider(t)
	v := verifier(t, p, oidc.Config{})
	ctx := context.Background()

	t.Run("alg none", func(t *testing.T) {
		// A token that says it is unsigned is a JSON object somebody typed.
		raw := sign(t, "", "none", claims(p, nil), nil)
		mustRefuse(t, v, raw, "none")
	})

	t.Run("HMAC with the public key as the secret", func(t *testing.T) {
		// ⛔ The oldest JWT attack: HS256 takes a shared secret, and a
		// verifier that reaches for the issuer's PUBLIC key to check one
		// accepts a token anybody can mint, because the key is public.
		//
		// This one is forged HERE rather than by pyjwt, which refuses to sign
		// it at all ("the specified key is an asymmetric key ... and should
		// not be used as an HMAC secret") -- a second implementation agreeing
		// that the shape is an attack, which is worth writing down.
		raw := forgeHS256(t, publicPEM(t, &p.rsaKey.PublicKey), claims(p, nil), "rsa-1")
		mustRefuse(t, v, raw, "HS256")
	})

	t.Run("signed by another key", func(t *testing.T) {
		other := newProvider(t)
		raw := sign(t, other.rsaPEM(t), "RS256", claims(p, nil), map[string]any{"kid": "rsa-1"})
		mustRefuse(t, v, raw, "verifies this")
	})

	t.Run("a kid the issuer does not publish", func(t *testing.T) {
		raw := sign(t, p.rsaPEM(t), "RS256", claims(p, nil), map[string]any{"kid": "rsa-99"})
		mustRefuse(t, v, raw, "no key")
	})

	t.Run("another issuer", func(t *testing.T) {
		c := claims(p, nil)
		c["iss"] = "https://login.example.org"
		raw := sign(t, p.rsaPEM(t), "RS256", c, map[string]any{"kid": "rsa-1"})
		mustRefuse(t, v, raw, "is from")
	})

	t.Run("an issuer that merely starts with the right one", func(t *testing.T) {
		// ⛔ "https://login.example.org.evil.test" starts with the right
		// string, and a prefix comparison is how a verifier trusts it.
		c := claims(p, nil)
		c["iss"] = p.URL + ".evil.test"
		raw := sign(t, p.rsaPEM(t), "RS256", c, map[string]any{"kid": "rsa-1"})
		mustRefuse(t, v, raw, "is from")
	})

	t.Run("another audience", func(t *testing.T) {
		c := claims(p, nil)
		c["aud"] = "somebody-else"
		raw := sign(t, p.rsaPEM(t), "RS256", c, map[string]any{"kid": "rsa-1"})
		mustRefuse(t, v, raw, "addressed to")
	})

	t.Run("expired", func(t *testing.T) {
		c := claims(p, nil)
		c["exp"] = time.Now().Add(-time.Hour).Unix()
		raw := sign(t, p.rsaPEM(t), "RS256", c, map[string]any{"kid": "rsa-1"})
		mustRefuse(t, v, raw, "expired")
	})

	t.Run("no expiry at all", func(t *testing.T) {
		// A token that never expires is a password somebody can copy once.
		c := claims(p, nil)
		delete(c, "exp")
		raw := sign(t, p.rsaPEM(t), "RS256", c, map[string]any{"kid": "rsa-1"})
		mustRefuse(t, v, raw, "no expiry")
	})

	t.Run("not valid yet", func(t *testing.T) {
		c := claims(p, nil)
		c["nbf"] = time.Now().Add(time.Hour).Unix()
		raw := sign(t, p.rsaPEM(t), "RS256", c, map[string]any{"kid": "rsa-1"})
		mustRefuse(t, v, raw, "not valid for another")
	})

	t.Run("a tampered payload", func(t *testing.T) {
		raw := sign(t, p.rsaPEM(t), "RS256", claims(p, map[string]any{"preferred_username": "dora"}), map[string]any{"kid": "rsa-1"})
		parts := strings.Split(raw, ".")
		// The signature is over the ENCODED header and payload as they
		// arrived, so changing one byte of the payload breaks it -- which is
		// the property a verifier that re-encodes before checking loses.
		tampered := parts[0] + "." + strings.Replace(parts[1], "A", "B", 1) + "." + parts[2]
		if _, err := v.Verify(ctx, tampered); err == nil {
			t.Error("a tampered payload was accepted")
		}
	})

	t.Run("not a token at all", func(t *testing.T) {
		for _, raw := range []string{"", "one.two", "one.two.three.four", "!!!.???.***"} {
			if _, err := v.Verify(ctx, raw); err == nil {
				t.Errorf("%q was accepted as a token", raw)
			}
		}
	})
}

// A clock that differs by a little is tolerated; by a lot is not.
func TestClockSkew(t *testing.T) {
	p := newProvider(t)
	c := claims(p, nil)
	c["exp"] = time.Now().Add(-30 * time.Second).Unix()
	raw := sign(t, p.rsaPEM(t), "RS256", c, map[string]any{"kid": "rsa-1"})

	// Default skew is a minute, so a token that expired thirty seconds ago is
	// still accepted -- clocks differ.
	if _, err := verifier(t, p, oidc.Config{}).Verify(context.Background(), raw); err != nil {
		t.Errorf("a token thirty seconds past its expiry was refused: %v", err)
	}
	// With no tolerance it is not.
	tight := verifier(t, p, oidc.Config{ClockSkew: time.Nanosecond})
	if _, err := tight.Verify(context.Background(), raw); err == nil {
		t.Error("a token past its expiry was accepted with no tolerance")
	}
}

// The audience is a list in the specification and a string in most tokens.
func TestAudienceIsAListOrAString(t *testing.T) {
	p := newProvider(t)
	v := verifier(t, p, oidc.Config{})
	c := claims(p, nil)
	c["aud"] = []string{"somebody-else", "fileshare"}
	raw := sign(t, p.rsaPEM(t), "RS256", c, map[string]any{"kid": "rsa-1"})
	tok, err := v.Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("a token addressed to two services including this one was refused: %v", err)
	}
	if len(tok.Audience()) != 2 {
		t.Errorf("Audience() = %v", tok.Audience())
	}
}

// A single group sent as a string is one group, not none: providers differ,
// and a server that read only lists would put that person in no groups at all.
func TestASingleGroupAsAString(t *testing.T) {
	p := newProvider(t)
	v := verifier(t, p, oidc.Config{})
	c := claims(p, map[string]any{"groups": "engineers"})
	raw := sign(t, p.rsaPEM(t), "RS256", c, map[string]any{"kid": "rsa-1"})
	tok, err := v.Verify(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(tok.Groups(), ","); got != "engineers" {
		t.Errorf("Groups() = %q", got)
	}
}

// Which claim names the person is a deployment's decision.
func TestTheClaimsAreNamed(t *testing.T) {
	p := newProvider(t)
	v := verifier(t, p, oidc.Config{UsernameClaim: "sub", GroupsClaim: "roles"})
	c := claims(p, map[string]any{
		"preferred_username": "dora",
		"email":              "dora@example.org",
		"roles":              []string{"admin"},
		"groups":             []string{"ignored"},
	})
	raw := sign(t, p.rsaPEM(t), "RS256", c, map[string]any{"kid": "rsa-1"})
	tok, err := v.Verify(context.Background(), raw)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Username() != "user-1" {
		t.Errorf("Username() = %q, want the sub", tok.Username())
	}
	if got := strings.Join(tok.Groups(), ","); got != "admin" {
		t.Errorf("Groups() = %q", got)
	}
	// And an arbitrary claim, for what this package has no opinion about.
	var email string
	if err := tok.Claim("email", &email); err != nil || email == "" {
		t.Errorf("Claim(email) = %q, %v", email, err)
	}
	if err := tok.Claim("absent", &email); err == nil {
		t.Error("a claim that is not there was read")
	}
	if !tok.Has("roles") || tok.Has("absent") {
		t.Error("Has disagrees with the claims")
	}
}

// mustRefuse fails unless the token is refused, and says how it was refused.
func mustRefuse(t *testing.T, v *oidc.Verifier, raw, because string) {
	t.Helper()
	_, err := v.Verify(context.Background(), raw)
	if err == nil {
		t.Fatal("the token was ACCEPTED")
	}
	if !strings.Contains(err.Error(), because) {
		t.Errorf("refused with %q, want one mentioning %q", err, because)
	}
}

// claims is a token a provider would sign, with whatever the test changes.
func claims(p *provider, extra map[string]any) map[string]any {
	issuer := p.url
	if issuer == "" {
		issuer = p.URL
	}
	c := map[string]any{
		"iss": issuer,
		"sub": "user-1",
		"aud": "fileshare",
		"exp": time.Now().Add(time.Hour).Unix(),
		"iat": time.Now().Unix(),
	}
	for k, v := range extra {
		c[k] = v
	}
	return c
}

// verifier is one pointed at the fixture, with the test's own settings.
func verifier(t *testing.T, p *provider, cfg oidc.Config) *oidc.Verifier {
	t.Helper()
	if cfg.Issuer == "" {
		cfg.Issuer = p.URL
	}
	if cfg.Audience == "" {
		cfg.Audience = "fileshare"
	}
	v, err := oidc.New(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	return v
}
