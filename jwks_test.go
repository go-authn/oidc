package oidc_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-authn/oidc"
)

// Every kind of key a provider publishes, and every kind that is not one.
func TestTheKeysAKeySetMayHold(t *testing.T) {
	ctx := context.Background()
	p := newProvider(t)

	// An Ed25519 key, signed by pyjwt: the third family, after RSA and EC.
	v := verifier(t, p, oidc.Config{})
	raw := sign(t, privatePEM(t, p.edKey), "EdDSA", claims(p, nil), map[string]any{"kid": "ed-1"})
	if _, err := v.Verify(ctx, raw); err != nil {
		t.Errorf("an EdDSA token was refused: %v", err)
	}

	// A key set holding one unreadable key alongside a good one still works:
	// an issuer adding a kind this package does not know must not take a
	// server down.
	p2 := newProvider(t)
	p2.keysBody = mustJSON(map[string]any{"keys": []any{
		map[string]any{"kty": "OCT", "kid": "sym-1"},
		p2.rsaJWK(),
	}})
	v2, err := oidc.New(ctx, oidc.Config{Issuer: p2.URL, Audience: "fileshare"})
	if err != nil {
		t.Fatalf("a key set with one unreadable key was refused entirely: %v", err)
	}
	raw = sign(t, p2.rsaPEM(t), "RS256", claims(p2, nil), map[string]any{"kid": "rsa-1"})
	if _, err := v2.Verify(ctx, raw); err != nil {
		t.Errorf("the readable key was not used: %v", err)
	}
}

// ⛔ Keys that are not keys. Each of these is a published JWK that a verifier
// must not turn into something it does arithmetic with.
func TestKeysThatAreRefused(t *testing.T) {
	small, err := rsaOfBits(1024)
	if err != nil {
		t.Fatal(err)
	}
	offCurve := map[string]any{
		"kty": "EC", "kid": "ec-bad", "crv": "P-256",
		// A point that is not on the curve. Implementations have been
		// persuaded to compute with one.
		"x": b64(make([]byte, 32)), "y": b64(make([]byte, 32)),
	}
	for _, tc := range []struct {
		name string
		jwk  map[string]any
	}{
		{"an RSA key of 1024 bits", small},
		{"a point that is not on the curve", offCurve},
		{"an EC key on a curve nobody named", map[string]any{"kty": "EC", "kid": "x", "crv": "P-192", "x": b64(make([]byte, 24)), "y": b64(make([]byte, 24))}},
		{"an Ed25519 key of the wrong length", map[string]any{"kty": "OKP", "kid": "x", "crv": "Ed25519", "x": b64(make([]byte, 16))}},
		{"an OKP key on another curve", map[string]any{"kty": "OKP", "kid": "x", "crv": "X25519", "x": b64(make([]byte, 32))}},
		{"a key of a kind nobody has", map[string]any{"kty": "MAGIC", "kid": "x"}},
		{"an EC point of the wrong length", map[string]any{"kty": "EC", "kid": "x", "crv": "P-256", "x": b64(make([]byte, 8)), "y": b64(make([]byte, 8))}},
		{"base64 that is not", map[string]any{"kty": "RSA", "kid": "x", "n": "!!!", "e": "AQAB"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newProvider(t)
			p.keysBody = mustJSON(map[string]any{"keys": []any{tc.jwk}})
			_, err := oidc.New(context.Background(), oidc.Config{Issuer: p.URL, Audience: "fileshare"})
			if err == nil {
				t.Error("the key was accepted")
			} else if !strings.Contains(err.Error(), "no key this can read") {
				t.Errorf("error = %v", err)
			}
		})
	}
}

// A key published for ENCRYPTION is not a key to check signatures with, and a
// key set legitimately holds both.
func TestAKeyForEncryptionIsNotForSignatures(t *testing.T) {
	p := newProvider(t)
	enc := p.rsaJWK()
	enc["use"] = "enc"
	enc["kid"] = "rsa-enc"
	p.keysBody = mustJSON(map[string]any{"keys": []any{enc}})
	_, err := oidc.New(context.Background(), oidc.Config{Issuer: p.URL, Audience: "fileshare"})
	if err == nil || !strings.Contains(err.Error(), "no key this can read") {
		t.Errorf("a set holding only an encryption key gave %v", err)
	}
}

// A key set published without kids: every key is a candidate, and the
// signature decides.
func TestAKeySetWithoutKids(t *testing.T) {
	p := newProvider(t)
	rsa := p.rsaJWK()
	delete(rsa, "kid")
	ec := p.ecJWK()
	delete(ec, "kid")
	p.keysBody = mustJSON(map[string]any{"keys": []any{ec, rsa}})
	v, err := oidc.New(context.Background(), oidc.Config{Issuer: p.URL, Audience: "fileshare"})
	if err != nil {
		t.Fatal(err)
	}
	// Signed with the second of the two, and named by neither.
	raw := sign(t, p.rsaPEM(t), "RS256", claims(p, nil), nil)
	if _, err := v.Verify(context.Background(), raw); err != nil {
		t.Errorf("a token from a set with no kids was refused: %v", err)
	}
	// And a token nothing in the set signed is still refused.
	other := newProvider(t)
	raw = sign(t, other.rsaPEM(t), "RS256", claims(p, nil), nil)
	if _, err := v.Verify(context.Background(), raw); err == nil {
		t.Error("a token signed by a key the set does not hold was accepted")
	}
}

// A key set that answers with something else entirely.
func TestAKeySetThatIsNotOne(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"not JSON", "<html>404</html>", 200},
		{"an error", "", 500},
	} {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if strings.HasSuffix(r.URL.Path, "openid-configuration") {
					json.NewEncoder(w).Encode(map[string]any{"issuer": "http://" + r.Host, "jwks_uri": "http://" + r.Host + "/keys"})
					return
				}
				w.WriteHeader(tc.status)
				fmt.Fprint(w, tc.body)
			}))
			defer srv.Close()
			if _, err := oidc.New(ctx, oidc.Config{Issuer: srv.URL, Audience: "fileshare"}); err == nil {
				t.Error("the key set was accepted")
			}
		})
	}
	// And a discovery document that is not JSON.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "not json")
	}))
	defer srv.Close()
	if _, err := oidc.New(ctx, oidc.Config{Issuer: srv.URL, Audience: "fileshare"}); err == nil {
		t.Error("a discovery document that is not JSON was accepted")
	}
}

// The corners of the token format itself.
func TestTokensThatAreNotWellFormed(t *testing.T) {
	p := newProvider(t)
	v := verifier(t, p, oidc.Config{})
	ctx := context.Background()

	good := sign(t, p.rsaPEM(t), "RS256", claims(p, nil), map[string]any{"kid": "rsa-1"})
	parts := strings.Split(good, ".")
	for _, tc := range []struct{ name, raw string }{
		{"a header that is not base64", "!!!." + parts[1] + "." + parts[2]},
		{"a signature that is not base64", parts[0] + "." + parts[1] + ".!!!"},
		{"a payload that is not base64", parts[0] + ".!!!." + parts[2]},
		{"a header that is not JSON", b64([]byte("not json")) + "." + parts[1] + "." + parts[2]},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := v.Verify(ctx, tc.raw); err == nil {
				t.Error("it was accepted")
			}
		})
	}
	// A token typed as something else: a JWE, for instance, which is not a
	// signed token at all.
	raw := sign(t, p.rsaPEM(t), "RS256", claims(p, nil), map[string]any{"kid": "rsa-1", "typ": "JOSE+JSON"})
	if _, err := v.Verify(ctx, raw); err == nil || !strings.Contains(err.Error(), "type") {
		t.Errorf("a token of another type gave %v", err)
	}
	// An access token says at+jwt (RFC 9068) and is a token.
	raw = sign(t, p.rsaPEM(t), "RS256", claims(p, nil), map[string]any{"kid": "rsa-1", "typ": "at+jwt"})
	if _, err := v.Verify(ctx, raw); err != nil {
		t.Errorf("an RFC 9068 access token was refused: %v", err)
	}
}

func rsaOfBits(bits int) (map[string]any, error) {
	key, err := rsaGenerate(bits)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"kty": "RSA", "kid": "small", "n": b64(key.N.Bytes()), "e": b64([]byte{1, 0, 1}),
	}, nil
}

func mustJSON(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func rsaGenerate(bits int) (*rsa.PublicKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, err
	}
	return &key.PublicKey, nil
}
