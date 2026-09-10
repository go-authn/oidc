package oidc_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"testing"
)

// privatePEM writes a key in the PKCS#8 PEM that every other language reads.
func privatePEM(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

// publicPEM is the public key in the SubjectPublicKeyInfo PEM -- which is what
// an attacker trying the HMAC confusion has, because it is public.
func publicPEM(t *testing.T, key any) string {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
}

// forgeHS256 builds the attack token: the header says HS256, and the "secret"
// is the issuer's PUBLIC key, which anybody can fetch.
//
// It is written by hand because pyjwt refuses to produce it -- an independent
// implementation agreeing that the shape is an attack rather than a use.
func forgeHS256(t *testing.T, publicKeyPEM string, claims map[string]any, kid string) string {
	t.Helper()
	header, err := json.Marshal(map[string]any{"alg": "HS256", "typ": "JWT", "kid": kid})
	if err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding
	signing := enc.EncodeToString(header) + "." + enc.EncodeToString(payload)
	mac := hmac.New(sha256.New, []byte(publicKeyPEM))
	mac.Write([]byte(signing))
	return signing + "." + enc.EncodeToString(mac.Sum(nil))
}

// ecKeyOn generates a key on a named curve and the JWK that publishes it.
func ecKeyOn(t *testing.T, name string) (*ecdsa.PrivateKey, map[string]any) {
	t.Helper()
	curves := map[string]struct {
		curve elliptic.Curve
		size  int
	}{
		"P-256": {elliptic.P256(), 32},
		"P-384": {elliptic.P384(), 48},
		"P-521": {elliptic.P521(), 66},
	}
	c, ok := curves[name]
	if !ok {
		t.Fatalf("no curve %q", name)
	}
	key, err := ecdsa.GenerateKey(c.curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key, map[string]any{
		"kty": "EC", "kid": "ec-x", "use": "sig", "crv": name,
		"x": base64.RawURLEncoding.EncodeToString(key.X.FillBytes(make([]byte, c.size))),
		"y": base64.RawURLEncoding.EncodeToString(key.Y.FillBytes(make([]byte, c.size))),
	}
}
