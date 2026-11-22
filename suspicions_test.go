// SPDX-License-Identifier: BSD-3-Clause

package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"strings"
	"testing"
)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// Suspicion 5, RFC 7518 §3.4: ES256 is P-256 with SHA-256. A P-384 key must
// not verify an ES256 token, whatever the signature length says.
func TestESAlgorithmsNeedTheirCurve(t *testing.T) {
	signed := []byte("header.payload")
	sign := func(t *testing.T, c elliptic.Curve, size int, sum func([]byte) []byte) (*ecdsa.PublicKey, []byte) {
		k, err := ecdsa.GenerateKey(c, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		r, s, err := ecdsa.Sign(rand.Reader, k, sum(signed))
		if err != nil {
			t.Fatal(err)
		}
		sig := append(r.FillBytes(make([]byte, size)), s.FillBytes(make([]byte, size))...)
		return &k.PublicKey, sig
	}
	s256 := func(b []byte) []byte { d := sha256.Sum256(b); return d[:] }
	s384 := func(b []byte) []byte { d := sha512.Sum384(b); return d[:] }
	s512 := func(b []byte) []byte { d := sha512.Sum512(b); return d[:] }

	k384, sig384 := sign(t, elliptic.P384(), 48, s256)
	if err := verifySignature("ES256", k384, signed, sig384); err == nil {
		t.Error("ES256 verified with a P-384 key")
	}
	k521, sig521 := sign(t, elliptic.P521(), 66, s256)
	if err := verifySignature("ES256", k521, signed, sig521); err == nil {
		t.Error("ES256 verified with a P-521 key")
	}
	for _, tc := range []struct {
		alg  string
		c    elliptic.Curve
		size int
		sum  func([]byte) []byte
	}{
		{"ES256", elliptic.P256(), 32, s256},
		{"ES384", elliptic.P384(), 48, s384},
		{"ES512", elliptic.P521(), 66, s512},
	} {
		k, sig := sign(t, tc.c, tc.size, tc.sum)
		if err := verifySignature(tc.alg, k, signed, sig); err != nil {
			t.Errorf("%s with its own curve: %v", tc.alg, err)
		}
	}
	k, sig := sign(t, elliptic.P256(), 32, s384)
	if err := verifySignature("ES384", k, signed, sig); err == nil {
		t.Error("ES384 verified with a P-256 key")
	}
}

// Suspicion 5, the second half, RFC 7517 §4.4: a key published for RS256 does
// not verify an RS512 token.
func TestJWKAlgIsHonoured(t *testing.T) {
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	doc := func(alg string) string {
		j := map[string]any{"kty": "RSA", "kid": "k", "use": "sig", "n": b64(k.N.Bytes()), "e": b64(big.NewInt(int64(k.E)).Bytes())}
		if alg != "" {
			j["alg"] = alg
		}
		b, _ := json.Marshal(map[string]any{"keys": []any{j}})
		return string(b)
	}
	signed := []byte("header.payload")
	d := sha512.Sum512(signed)
	sig, err := rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA512, d[:])
	if err != nil {
		t.Fatal(err)
	}
	try := func(published string) error {
		keys, untyped, err := parseKeySet(strings.NewReader(doc(published)))
		if err != nil {
			t.Fatal(err)
		}
		ks := &keySet{keys: keys, untyped: untyped}
		return ks.tryHeld(joseHeader{Alg: "RS512", Kid: "k"}, signed, sig)
	}
	if err := try("RS256"); err == nil {
		t.Error("an RS512 token verified with a key published for RS256")
	}
	if err := try("RS512"); err != nil {
		t.Errorf("the key's own algorithm: %v", err)
	}
	if err := try(""); err != nil {
		t.Errorf("a key with no alg: %v", err)
	}
	// And without a kid.
	keys, untyped, _ := parseKeySet(strings.NewReader(strings.Replace(doc("RS256"), `"kid":"k",`, "", 1)))
	ks := &keySet{keys: keys, untyped: untyped}
	if err := ks.tryHeld(joseHeader{Alg: "RS512"}, signed, sig); err == nil {
		t.Error("a key without kid published for RS256 verified an RS512 token")
	}
}

// Suspicion 6: the routing claim is "iss" exactly, as the verifier reads it.
func TestPeekIssuerIsCaseSensitive(t *testing.T) {
	tok := func(payload string) string {
		return b64([]byte(`{"alg":"ES256"}`)) + "." + b64([]byte(payload)) + ".c2ln"
	}
	if iss, ok := PeekIssuer(tok(`{"ISS":"https://a.example"}`)); ok {
		t.Errorf("routed on ISS: %q", iss)
	}
	if iss, ok := PeekIssuer(tok(`{"Iss":"https://a.example"}`)); ok {
		t.Errorf("routed on Iss: %q", iss)
	}
	if iss, ok := PeekIssuer(tok(`{"iss":"https://a.example","ISS":"https://b.example"}`)); !ok || iss != "https://a.example" {
		t.Errorf("iss next to ISS: %q %v", iss, ok)
	}
	if iss, ok := PeekIssuer(tok(`{"iss":"https://a.example"}`)); !ok || iss != "https://a.example" {
		t.Errorf("plain: %q %v", iss, ok)
	}
	if _, ok := PeekIssuer(tok(`{"iss":5}`)); ok {
		t.Error("a number as issuer")
	}
	if _, ok := PeekIssuer(tok(`{}`)); ok {
		t.Error("no issuer")
	}
}
