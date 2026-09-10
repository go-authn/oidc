package oidc_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/oidc"
)

// What a token says when the provider says less than the usual.
func TestClaimsThatAreMissingOrOddlyShaped(t *testing.T) {
	p := newProvider(t)
	ctx := context.Background()

	// No preferred_username and no email: the name falls back to sub, which
	// every token has and which is the one the issuer promises is stable.
	v := verifier(t, p, oidc.Config{})
	raw := sign(t, p.rsaPEM(t), "RS256", claims(p, nil), map[string]any{"kid": "rsa-1"})
	tok, err := v.Verify(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Username() != "user-1" {
		t.Errorf("Username() = %q, want the sub", tok.Username())
	}
	if tok.Groups() != nil {
		t.Errorf("Groups() = %v, want none", tok.Groups())
	}
	if tok.Email() != "" || tok.EmailVerified() {
		t.Error("an email appeared from a token that carries none")
	}
	if at, ok := tok.IssuedAt(); !ok || time.Since(at) > time.Minute {
		t.Errorf("IssuedAt() = %v, %v", at, ok)
	}
	if _, ok := tok.NotBefore(); ok {
		t.Error("a nbf appeared from a token that carries none")
	}
	if tok.Issuer() != p.URL {
		t.Errorf("Issuer() = %q", tok.Issuer())
	}

	// A configured claim that the token does not carry is an empty name --
	// not a fallback. A deployment that named a claim meant that claim, and
	// quietly using another is how somebody is admitted under the wrong name.
	named := verifier(t, p, oidc.Config{UsernameClaim: "nickname"})
	tok, err = named.Verify(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Username() != "" {
		t.Errorf("Username() = %q, want empty: the named claim is not there", tok.Username())
	}

	// Claims of the wrong shape read as absent rather than as something else.
	raw = sign(t, p.rsaPEM(t), "RS256", claims(p, map[string]any{
		"preferred_username": 42,
		"groups":             map[string]any{"not": "a list"},
		"email_verified":     "yes",
	}), map[string]any{"kid": "rsa-1"})
	tok, err = v.Verify(ctx, raw)
	if err != nil {
		t.Fatal(err)
	}
	if tok.Username() != "user-1" {
		t.Errorf("a numeric preferred_username became %q", tok.Username())
	}
	if tok.Groups() != nil {
		t.Errorf("Groups() = %v", tok.Groups())
	}
	if tok.EmailVerified() {
		t.Error("email_verified: \"yes\" was read as true")
	}
	if tok.Audience() == nil {
		t.Error("Audience() = nil")
	}
}

// An expiry that is not a number is not an expiry.
func TestATokenWhoseExpiryIsNotOne(t *testing.T) {
	p := newProvider(t)
	v := verifier(t, p, oidc.Config{})
	c := claims(p, nil)
	c["exp"] = "soon"
	raw := sign(t, p.rsaPEM(t), "RS256", c, map[string]any{"kid": "rsa-1"})
	if _, err := v.Verify(context.Background(), raw); err == nil || !strings.Contains(err.Error(), "no expiry") {
		t.Errorf("error = %v", err)
	}
}

// A NumericDate may carry a fraction (RFC 7519 §2).
func TestAFractionalExpiry(t *testing.T) {
	p := newProvider(t)
	v := verifier(t, p, oidc.Config{})
	c := claims(p, nil)
	c["exp"] = float64(time.Now().Add(time.Hour).UnixNano()) / 1e9
	raw := sign(t, p.rsaPEM(t), "RS256", c, map[string]any{"kid": "rsa-1"})
	tok, err := v.Verify(context.Background(), raw)
	if err != nil {
		t.Fatalf("a fractional expiry was refused: %v", err)
	}
	if exp, ok := tok.Expiry(); !ok || exp.Before(time.Now()) {
		t.Errorf("Expiry() = %v, %v", exp, ok)
	}
}

// The curves a provider may publish, and one it may not.
func TestTheCurves(t *testing.T) {
	for _, curve := range []string{"P-384", "P-521"} {
		t.Run(curve, func(t *testing.T) {
			p := newProvider(t)
			key, jwk := ecKeyOn(t, curve)
			p.keysBody = mustJSON(map[string]any{"keys": []any{jwk}})
			v, err := oidc.New(context.Background(), oidc.Config{Issuer: p.URL, Audience: "fileshare"})
			if err != nil {
				t.Fatal(err)
			}
			alg := map[string]string{"P-384": "ES384", "P-521": "ES512"}[curve]
			raw := sign(t, privatePEM(t, key), alg, claims(p, nil), map[string]any{"kid": "ec-x"})
			if _, err := v.Verify(context.Background(), raw); err != nil {
				t.Errorf("%s was refused: %v", curve, err)
			}
		})
	}
}

// A hostname that only looks like loopback is not loopback.
func TestWhatCountsAsLoopback(t *testing.T) {
	for _, issuer := range []string{
		"http://localhost.evil.test/realms/x",
		"http://127.0.0.1.evil.test/",
		"http://127.0.0.1.evil.test:8080/",
	} {
		if _, err := oidc.New(context.Background(), oidc.Config{Issuer: issuer, Audience: "x"}); err == nil ||
			!strings.Contains(err.Error(), "not https") {
			t.Errorf("%s gave %v", issuer, err)
		}
	}
	// A bracketed host that is not a real address is refused as not a URL,
	// which is a different message and the right one.
	if _, err := oidc.New(context.Background(), oidc.Config{Issuer: "http://[::1].evil.test/", Audience: "x"}); err == nil {
		t.Error("a malformed host was accepted")
	}
	// And something that is not a URL at all.
	if _, err := oidc.New(context.Background(), oidc.Config{Issuer: "://nonsense", Audience: "x"}); err == nil {
		t.Error("a string that is not a URL was accepted as an issuer")
	}
}
