// SPDX-License-Identifier: BSD-3-Clause

package oidc

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"math"
	"os"
	"strings"
	"testing"
)

// The parsers that read what arrives from the network, fuzzed where they
// live: the compact serialisation and its base64url, the header and claims
// JSON, and JWK / JWK Set parsing. Each target states the property it holds,
// not only that nothing panics.

// fixture is testdata/fixed.json: tokens signed by pyjwt and their key set.
type fixture struct {
	JWKS  json.RawMessage `json:"jwks"`
	RS256 string          `json:"rs256"`
	PS256 string          `json:"ps256"`
	ES256 string          `json:"es256"`
}

func loadFixture(tb testing.TB) fixture {
	tb.Helper()
	raw, err := os.ReadFile("testdata/fixed.json")
	if err != nil {
		tb.Fatal(err)
	}
	var f fixture
	if err := json.Unmarshal(raw, &f); err != nil {
		tb.Fatal(err)
	}
	return f
}

func b64u(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// FuzzDecode: base64url has one spelling. Whatever decodes re-encodes to the
// very string that arrived, so one signed token is never several strings.
func FuzzDecode(f *testing.F) {
	for _, s := range []string{"", "AA", "AQ", "AB", "AAA", "A\nA", "A=", "-_", "eyJhbGciOiJSUzI1NiJ9"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		b, err := decode(s)
		if err != nil {
			return
		}
		if got := base64.RawURLEncoding.EncodeToString(b); got != s {
			t.Fatalf("decode(%q) = %x, which encodes as %q", s, b, got)
		}
	})
}

// FuzzSplit: a token that splits has three canonical parts, its signing input
// is the first two exactly as sent, and its header was JSON.
func FuzzSplit(f *testing.F) {
	fx := loadFixture(f)
	for _, s := range []string{
		fx.RS256, fx.PS256, fx.ES256,
		// The refusals the README names, in their wire form.
		b64u(`{"alg":"none"}`) + "." + b64u(`{"sub":"x"}`) + ".",
		b64u(`{"alg":"HS256","kid":"k"}`) + "." + b64u(`{"sub":"x"}`) + ".c2ln",
		b64u(`{"alg":"RS256","typ":"JWT"}`) + "." + b64u(`{"iss":"https://login.example.org.evil.test"}`) + ".c2ln",
		"a.b", "a.b.c.d", "..", "...", b64u("not json") + "." + b64u("{}") + ".",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		header, payload, signed, signature, err := split(raw)
		if err != nil {
			return
		}
		parts := strings.Split(raw, ".")
		if len(parts) != 3 || string(signed) != parts[0]+"."+parts[1] {
			t.Fatalf("signing input %q of %q", signed, raw)
		}
		if b64u(string(payload)) != parts[1] || base64.RawURLEncoding.EncodeToString(signature) != parts[2] {
			t.Fatalf("parts of %q do not re-encode", raw)
		}
		_ = header
		// The header gate Verify applies next: nothing outside the list.
		if signatureAlgorithms[header.Alg] && (header.Alg == "none" || strings.HasPrefix(header.Alg, "HS")) {
			t.Fatalf("algorithm %q would be accepted", header.Alg)
		}
	})
}

// FuzzClaims: whatever payload verified, the accessors never panic, and a
// time claim that reads is the time the claim says (no overflow turning a
// date in the far future into one in the past).
func FuzzClaims(f *testing.F) {
	for _, s := range []string{
		`{"sub":"u","aud":["a","b"],"exp":1767225600.5,"nbf":0,"groups":"one"}`,
		`{"aud":"a","exp":"soon","email":"x@y","email_verified":"true"}`,
		`{"exp":1e300,"nbf":1e19,"iat":-1e19}`,
		`{"exp":9223372036.854775807}`, `{"groups":[1,2]}`, `[]`, `null`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, payload string) {
		var tok Token
		if json.Unmarshal([]byte(payload), &tok.claims) != nil {
			return
		}
		_ = tok.Username() + tok.Subject() + tok.Issuer() + tok.Email()
		_, _ = tok.Groups(), tok.Audience()
		_ = tok.forAudience("a") && tok.EmailVerified()
		for _, name := range []string{"exp", "nbf", "iat"} {
			got, ok := tok.time(name)
			if !ok {
				continue
			}
			var seconds float64
			if err := json.Unmarshal(tok.claims[name], &seconds); err != nil {
				t.Fatalf("%s read as a time but is not a number", name)
			}
			// Out-of-range dates are held to years 1-9999: never wrapped.
			seconds = min(max(seconds, minNumericDate), maxNumericDate)
			if d := float64(got.Unix()) - seconds; math.Abs(d) > 1 {
				t.Fatalf("%s = %v read as %v (Unix %d)", name, seconds, got, got.Unix())
			}
		}
	})
}

// Regression for what FuzzClaims found: an "nbf" far in the future wrapped
// to the far past and a token not yet valid was accepted; an "nbf" that is
// not a date was ignored.
func TestNotBeforeOutOfRange(t *testing.T) {
	v := &Verifier{cfg: Config{Issuer: "https://login.example.test", Audience: "fileshare"}}
	for payload, want := range map[string]bool{
		`{"iss":"https://login.example.test","aud":"fileshare","exp":1e300}`:               true,
		`{"iss":"https://login.example.test","aud":"fileshare","exp":1e300,"nbf":1}`:       true,
		`{"iss":"https://login.example.test","aud":"fileshare","exp":1e300,"nbf":1e19}`:    false,
		`{"iss":"https://login.example.test","aud":"fileshare","exp":1e300,"nbf":"soon"}`:  false,
		`{"iss":"https://login.example.test","aud":"fileshare","exp":-1e19}`:               false,
		`{"iss":"https://login.example.test","aud":"fileshare","exp":9223372036854775807}`: true,
		`{"iss":"https://login.example.test","aud":"fileshare","exp":1e300,"nbf":-1e300}`:  true,
	} {
		var tok Token
		if err := json.Unmarshal([]byte(payload), &tok.claims); err != nil {
			t.Fatal(err)
		}
		if err := v.check(&tok); (err == nil) != want {
			t.Errorf("%s: %v, want accepted = %v", payload, err, want)
		}
	}
}

// FuzzJWK: a key that parses is one crypto can use safely: RSA of at least
// 2048 bits with an odd exponent of at least 3, an EC point on its curve, an
// Ed25519 key of 32 bytes.
func FuzzJWK(f *testing.F) {
	fx := loadFixture(f)
	var set struct {
		Keys []json.RawMessage `json:"keys"`
	}
	_ = json.Unmarshal(fx.JWKS, &set)
	for _, k := range set.Keys {
		f.Add(string(k))
	}
	for _, s := range []string{
		`{"kty":"RSA","n":"AQAB","e":"AQAB"}`, `{"kty":"RSA","n":"` + strings.Repeat("_", 342) + `","e":"AQ"}`,
		`{"kty":"RSA","n":"` + strings.Repeat("_", 342) + `","e":"Ag"}`,
		`{"kty":"EC","crv":"P-256","x":"AA","y":"AA"}`, `{"kty":"OKP","crv":"Ed25519","x":"` + strings.Repeat("A", 43) + `"}`,
		`{"kty":"OKP","crv":"X25519","x":"AA"}`, `{"kty":"oct","k":"c2VjcmV0"}`,
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		var j jwk
		if json.Unmarshal([]byte(s), &j) != nil {
			return
		}
		key, err := j.parse()
		if err != nil {
			return
		}
		switch k := key.(type) {
		case *rsa.PublicKey:
			if k.N.BitLen() < 2048 || k.E < 3 || k.E%2 == 0 {
				t.Fatalf("RSA key accepted: %d bits, e = %d", k.N.BitLen(), k.E)
			}
		case *ecdsa.PublicKey:
			if !k.Curve.IsOnCurve(k.X, k.Y) {
				t.Fatal("EC point off its curve accepted")
			}
		case ed25519.PublicKey:
			if len(k) != ed25519.PublicKeySize {
				t.Fatalf("Ed25519 key of %d bytes", len(k))
			}
		default:
			t.Fatalf("a key of type %T", key)
		}
	})
}

// FuzzKeySet: a set either yields keys or an error, never both empty.
func FuzzKeySet(f *testing.F) {
	fx := loadFixture(f)
	f.Add(string(fx.JWKS))
	f.Add(`{"keys":[]}`)
	f.Add(`{"keys":[{"kty":"RSA","use":"enc","n":"AQAB","e":"AQAB"}]}`)
	f.Add(`{"keys":null}`)
	f.Add(`[`)
	f.Fuzz(func(t *testing.T, s string) {
		keys, untyped, err := parseKeySet(strings.NewReader(s))
		if err == nil && len(keys) == 0 && len(untyped) == 0 {
			t.Fatal("an empty key set without an error")
		}
		for kid, k := range keys {
			if kid == "" || k == nil {
				t.Fatalf("key %q: %v", kid, k)
			}
		}
	})
}
