package oidc_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/go-authn/oidc"
)

// Tokens signed once, by pyjwt, and committed.
//
// The tests next door sign a fresh token for each case, which needs pyjwt
// installed -- so they skip where it is not, and that is every architecture
// lane: the ones running under qemu, where a byte-order mistake would show.
// This one needs nothing but the repository, so s390x (big-endian) verifies
// the same signatures every other machine does.
//
// ⛔ The clock is fixed, because a committed token expires. Everything else
// about it is real: the key set is the one that signed them, and changing a
// byte of either file fails this test.
func TestTokensSignedOnceAndCommitted(t *testing.T) {
	var fixture struct {
		JWKS   json.RawMessage `json:"jwks"`
		RS256  string          `json:"rs256"`
		PS256  string          `json:"ps256"`
		ES256  string          `json:"es256"`
		Claims map[string]any  `json:"claims"`
	}
	raw, err := os.ReadFile("testdata/fixed.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "openid-configuration") {
			// The issuer in the tokens is a name, not this test server: the
			// verifier is told the JWKS directly, which is the case a
			// provider behind something that does not forward discovery
			// needs anyway.
			fmt.Fprint(w, "{}")
			return
		}
		w.Write(fixture.JWKS)
	}))
	defer srv.Close()

	// 2026-01-01, comfortably inside the tokens' validity and fixed so that
	// this test says the same thing in ten years as it does today.
	now := time.Unix(1767225600, 0)
	v, err := oidc.New(context.Background(), oidc.Config{
		Issuer:   "https://login.example.test",
		Audience: "fileshare",
		JWKSURL:  srv.URL + "/keys",
		Now:      func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ alg, token string }{
		{"RS256", fixture.RS256},
		{"PS256", fixture.PS256},
		{"ES256", fixture.ES256},
	} {
		t.Run(tc.alg, func(t *testing.T) {
			tok, err := v.Verify(context.Background(), tc.token)
			if err != nil {
				t.Fatalf("a committed %s token was refused: %v", tc.alg, err)
			}
			if tok.Subject() != "user-1" || tok.Username() != "dora" {
				t.Errorf("Subject() = %q, Username() = %q", tok.Subject(), tok.Username())
			}
			if got := strings.Join(tok.Groups(), ","); got != "engineers,oncall" {
				t.Errorf("Groups() = %q", got)
			}
			if !tok.EmailVerified() || tok.Email() != "dora@example.test" {
				t.Errorf("Email() = %q, verified = %v", tok.Email(), tok.EmailVerified())
			}
			// One byte changed in the payload is a different token.
			parts := strings.Split(tc.token, ".")
			bad := parts[0] + "." + strings.Replace(parts[1], "d", "e", 1) + "." + parts[2]
			if _, err := v.Verify(context.Background(), bad); err == nil {
				t.Error("a token with a changed payload was accepted")
			}
		})
	}

	// And the clock still decides: the same tokens are refused after they
	// expire, which is 2033 for these.
	late, err := oidc.New(context.Background(), oidc.Config{
		Issuer: "https://login.example.test", Audience: "fileshare", JWKSURL: srv.URL + "/keys",
		Now: func() time.Time { return time.Unix(2100000000, 0) },
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := late.Verify(context.Background(), fixture.RS256); err == nil || !strings.Contains(err.Error(), "expired") {
		t.Errorf("an expired token gave %v", err)
	}
}
