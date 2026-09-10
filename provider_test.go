package oidc_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
)

// A provider to verify against: the two documents a real one publishes, and
// nothing else.
//
// It is a fixture for the DISCOVERY and KEY SET halves. The tokens themselves
// are signed by pyjwt next door -- an implementation nobody here wrote --
// because a token this test file both makes and checks would only prove the
// two halves agree with each other.
type provider struct {
	*httptest.Server
	// url overrides what claims() puts in "iss", for a test whose tokens come
	// from one server and whose keys come from another.
	url    string
	rsaKey *rsa.PrivateKey
	ecKey  *ecdsa.PrivateKey
	edPub  ed25519.PublicKey
	edKey  ed25519.PrivateKey

	// Configurable so a test can break one thing at a time.
	issuerInDoc string
	jwksPath    string
	omitJWKS    bool
	keysBody    string
}

func newProvider(t *testing.T) *provider {
	t.Helper()
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p := &provider{rsaKey: rsaKey, ecKey: ecKey, edPub: edPub, edKey: edKey, jwksPath: "/keys"}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		issuer := p.issuerInDoc
		if issuer == "" {
			issuer = p.URL
		}
		doc := map[string]any{"issuer": issuer}
		if !p.omitJWKS {
			doc["jwks_uri"] = p.URL + p.jwksPath
		}
		json.NewEncoder(w).Encode(doc)
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		if p.keysBody != "" {
			fmt.Fprint(w, p.keysBody)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{p.rsaJWK(), p.ecJWK(), p.edJWK()}})
	})
	p.Server = httptest.NewServer(mux)
	t.Cleanup(p.Close)
	return p
}

func (p *provider) rsaJWK() map[string]any {
	return map[string]any{
		"kty": "RSA", "kid": "rsa-1", "use": "sig", "alg": "RS256",
		"n": b64(p.rsaKey.N.Bytes()),
		"e": b64(big.NewInt(int64(p.rsaKey.E)).Bytes()),
	}
}

func (p *provider) ecJWK() map[string]any {
	return map[string]any{
		"kty": "EC", "kid": "ec-1", "use": "sig", "alg": "ES256", "crv": "P-256",
		"x": b64(p.ecKey.X.FillBytes(make([]byte, 32))),
		"y": b64(p.ecKey.Y.FillBytes(make([]byte, 32))),
	}
}

func (p *provider) edJWK() map[string]any {
	return map[string]any{"kty": "OKP", "kid": "ed-1", "use": "sig", "alg": "EdDSA", "crv": "Ed25519", "x": b64(p.edPub)}
}

// rsaPEM is the private key, for pyjwt to sign with.
func (p *provider) rsaPEM(t *testing.T) string { return privatePEM(t, p.rsaKey) }
func (p *provider) ecPEM(t *testing.T) string  { return privatePEM(t, p.ecKey) }

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }
