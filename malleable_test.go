package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// ⛔ One signed token verifies as ONE string. Before v0.2.4 a newline or a CR
// inside a part, or flipped trailing bits in its last character, gave other
// strings that verified too (Go's base64 decoder skips \r\n and is lenient
// about trailing bits), which defeats a denylist or a replay cache keyed on
// the token as sent (security audit).
//
// ECDSA's s -> n-s is NOT refused, by choice: a standard signer (Go's
// ecdsa.Sign among them) produces the "high" s half the time, and refusing it
// would refuse half of all honest tokens. The README tells callers to key on
// jti or sub, never on the raw token; this test pins that the ONLY second
// spelling is that one.
func TestOneTokenVerifiesAsOneString(t *testing.T) {
	k, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b := func(x []byte) string { return base64.RawURLEncoding.EncodeToString(x) }
	pad := func(x *big.Int) []byte { o := make([]byte, 32); x.FillBytes(o); return o }
	jwks, _ := json.Marshal(map[string]any{"keys": []any{map[string]any{"kty": "EC", "crv": "P-256", "kid": "k1", "x": b(pad(k.X)), "y": b(pad(k.Y))}}})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write(jwks) }))
	defer srv.Close()
	v, err := New(context.Background(), Config{Issuer: "https://issuer.example", Audience: "app", JWKSURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	hdr := b([]byte(`{"alg":"ES256","kid":"k1"}`))
	pl := b([]byte(fmt.Sprintf(`{"iss":"https://issuer.example","aud":"app","sub":"alice","exp":%d,"jti":"once"}`, time.Now().Add(time.Hour).Unix())))
	d := sha256.Sum256([]byte(hdr + "." + pl))
	r, s, _ := ecdsa.Sign(rand.Reader, k, d[:])
	orig := hdr + "." + pl + "." + b(append(pad(r), pad(s)...))
	sig := orig[strings.LastIndex(orig, ".")+1:]
	last := sig[len(sig)-1]
	alpha := "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
	idx := strings.IndexByte(alpha, last)
	variants := map[string]string{
		"original":              orig,
		"newline in signature":  orig[:len(orig)-10] + "\n" + orig[len(orig)-10:],
		"CR inside signature":   orig[:len(orig)-20] + "\r" + orig[len(orig)-20:],
		"trailing bits flipped": orig[:len(orig)-1] + string(alpha[idx^1]),
		"ECDSA s -> n-s":        hdr + "." + pl + "." + b(append(pad(r), pad(new(big.Int).Sub(elliptic.P256().Params().N, s))...)),
	}
	for name, tok := range variants {
		_, err := v.Verify(context.Background(), tok)
		switch name {
		case "original", "ECDSA s -> n-s":
			if err != nil {
				t.Errorf("%s was refused: %v", name, err)
			}
		default:
			if err == nil {
				t.Errorf("%s verified: one token, another string", name)
			}
		}
	}
}
