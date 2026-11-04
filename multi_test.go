package oidc_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/go-authn/oidc"
)

func TestSetRoutesByIssuer(t *testing.T) {
	a, b := newProvider(t), newProvider(t)
	set, err := oidc.NewSet(verifier(t, a, oidc.Config{Audience: "svc-a"}), verifier(t, b, oidc.Config{Audience: "svc-b"}))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	tokA := sign(t, a.rsaPEM(t), "RS256", claims(a, map[string]any{"aud": "svc-a"}), map[string]any{"kid": "rsa-1"})
	tokB := sign(t, b.rsaPEM(t), "RS256", claims(b, map[string]any{"aud": "svc-b"}), map[string]any{"kid": "rsa-1"})
	for name, tc := range map[string]struct{ raw, iss string }{"a": {tokA, a.URL}, "b": {tokB, b.URL}} {
		tok, err := set.Verify(ctx, tc.raw)
		if err != nil || tok.Issuer() != tc.iss {
			t.Errorf("issuer %s: %v %v", name, tok, err)
		}
	}
	// Each issuer has its own audience.
	wrongAud := sign(t, a.rsaPEM(t), "RS256", claims(a, map[string]any{"aud": "svc-b"}), map[string]any{"kid": "rsa-1"})
	if _, err := set.Verify(ctx, wrongAud); err == nil {
		t.Error("b's audience accepted at a")
	}
	// Signed by b's key but claiming a's issuer: verified against a's keys only.
	forged := sign(t, b.rsaPEM(t), "RS256", claims(a, map[string]any{"aud": "svc-a"}), map[string]any{"kid": "rsa-1"})
	if _, err := set.Verify(ctx, forged); err == nil {
		t.Error("a token signed by b's key vouched for a")
	}
}

func TestSetUnknownIssuerCostsNoFetch(t *testing.T) {
	a, b, c := newProvider(t), newProvider(t), newProvider(t)
	set, err := oidc.NewSet(verifier(t, a, oidc.Config{}), verifier(t, b, oidc.Config{}))
	if err != nil {
		t.Fatal(err)
	}
	var hits atomic.Int64
	c.Server.Config.Handler = countHandler(c.Server.Config.Handler, &hits)
	raw := sign(t, c.rsaPEM(t), "RS256", claims(c, nil), map[string]any{"kid": "rsa-1"})
	if _, err := set.Verify(context.Background(), raw); !errors.Is(err, oidc.ErrUnknownIssuer) {
		t.Fatalf("unknown issuer: %v", err)
	}
	if hits.Load() != 0 {
		t.Fatalf("the unknown issuer was contacted %d times", hits.Load())
	}
	if _, err := set.For("not-a-token"); !errors.Is(err, oidc.ErrUnknownIssuer) {
		t.Fatalf("garbage: %v", err)
	}
}

func TestSetRefusesTwoVerifiersForOneIssuer(t *testing.T) {
	a := newProvider(t)
	if _, err := oidc.NewSet(verifier(t, a, oidc.Config{Audience: "x"}), verifier(t, a, oidc.Config{Audience: "y"})); err == nil {
		t.Fatal("two verifiers for one issuer")
	}
	if _, err := oidc.NewSet(nil); err == nil {
		t.Fatal("a nil verifier")
	}
}

func TestSingleVerifierSetRefusesAStranger(t *testing.T) {
	a, c := newProvider(t), newProvider(t)
	set, _ := oidc.NewSet(verifier(t, a, oidc.Config{}))
	raw := sign(t, c.rsaPEM(t), "RS256", claims(c, nil), map[string]any{"kid": "rsa-1"})
	if _, err := set.Verify(context.Background(), raw); err == nil {
		t.Fatal("a stranger's token")
	}
}

func TestPeekIssuer(t *testing.T) {
	b := func(s string) string { return strings.TrimRight(b64([]byte(s)), "=") }
	for _, tc := range []struct {
		raw string
		iss string
		ok  bool
	}{
		{"h." + b(`{"iss":"https://x"}`) + ".s", "https://x", true},
		{"h." + b(`{"iss":""}`) + ".s", "", false},
		{"h." + b(`{"iss":5}`) + ".s", "", false},
		{"h." + b(`{"iss":["a"]}`) + ".s", "", false},
		{"h." + b(`{}`) + ".s", "", false},
		{"h." + b(`not json`) + ".s", "", false},
		{"h.!!.s", "", false},
		{"h." + b(`{"iss":"x"}`), "", false},
		{"h." + b(`{"iss":"x"}`) + ".s.extra", "", false},
		{"h." + b(`{"iss":"x"}`) + strings.Repeat("a", oidc.MaxTokenSize), "", false},
	} {
		if iss, ok := oidc.PeekIssuer(tc.raw); iss != tc.iss || ok != tc.ok {
			t.Errorf("%.40q: %q %v", tc.raw, iss, ok)
		}
	}
}

func FuzzPeekIssuer(f *testing.F) {
	f.Add("h." + b64([]byte(`{"iss":"https://x"}`)) + ".s")
	f.Add("..")
	f.Fuzz(func(t *testing.T, raw string) {
		iss, ok := oidc.PeekIssuer(raw)
		if ok && (iss == "" || len(raw) > oidc.MaxTokenSize) {
			t.Fatalf("ok with %q for %d bytes", iss, len(raw))
		}
	})
}

// Check on verified tokens: absent, wrong, multi-valued, and non-string claims.
func TestCheckVerifiedTokens(t *testing.T) {
	a := newProvider(t)
	v := verifier(t, a, oidc.Config{})
	acc := []oidc.Accept{{Claim: "schac_home_organization", Values: []string{"univ-a.fr", "univ-b.fr"}}}
	for _, tc := range []struct {
		name  string
		extra map[string]any
		ok    bool
		shown string
	}{
		{"absent", nil, false, ""},
		{"right, other case", map[string]any{"schac_home_organization": "UNIV-A.fr"}, true, ""},
		{"wrong", map[string]any{"schac_home_organization": "univ-z.fr"}, false, "univ-z.fr"},
		{"multi-valued", map[string]any{"schac_home_organization": []string{"univ-z.fr", "univ-b.fr"}}, true, ""},
		{"multi-valued, none", map[string]any{"schac_home_organization": []string{"univ-y.fr", "univ-z.fr"}}, false, "univ-y.fr"},
		{"a number", map[string]any{"schac_home_organization": 5}, false, ""},
		{"an object", map[string]any{"schac_home_organization": map[string]any{"univ-a.fr": true}}, false, ""},
		{"a list with a number", map[string]any{"schac_home_organization": []any{"univ-a.fr", 5}}, false, ""},
		{"hostile", map[string]any{"schac_home_organization": "x\r\n<b>"}, false, "x<b>"},
	} {
		raw := sign(t, a.rsaPEM(t), "RS256", claims(a, tc.extra), map[string]any{"kid": "rsa-1"})
		tok, err := v.Verify(context.Background(), raw)
		if err != nil {
			t.Fatal(err)
		}
		r := oidc.Check(acc, tok)
		if (r == nil) != tc.ok || r != nil && r.Value != tc.shown {
			t.Errorf("%s: %+v", tc.name, r)
		}
	}
}
