package oidc_test

import (
	"context"
	"testing"

	"github.com/go-authn/oidc"
)

// ⛔ A resource server takes access tokens, and an ID token is not one even
// when its audience matches (RFC 9068 4: the resource server MUST check that
// typ is at+jwt). With Config.Type set, the header's typ is required to be
// that type, compared as RFC 7515 4.1.9 says: without case, application/
// optional. Unset, the old rule stands, since an ID token may carry any.
func TestATypeIsRequiredWhenOneIsAsked(t *testing.T) {
	p := newProvider(t)
	strict := verifier(t, p, oidc.Config{Type: "at+jwt"})
	lax := verifier(t, p, oidc.Config{})
	ctx := context.Background()

	for _, typ := range []string{"at+jwt", "AT+JWT", "application/at+jwt", "Application/AT+JWT"} {
		raw := sign(t, p.rsaPEM(t), "RS256", claims(p, nil), map[string]any{"kid": "rsa-1", "typ": typ})
		if _, err := strict.Verify(ctx, raw); err != nil {
			t.Errorf("typ %q was refused: %v", typ, err)
		}
	}
	for _, typ := range []string{"JWT", "", "logout+jwt", "application/jwt", "at+jwtx"} {
		headers := map[string]any{"kid": "rsa-1"}
		if typ != "" {
			headers["typ"] = typ
		}
		raw := sign(t, p.rsaPEM(t), "RS256", claims(p, nil), headers)
		mustRefuse(t, strict, raw, "type")
		if typ == "JWT" || typ == "" || typ == "application/jwt" {
			if _, err := lax.Verify(ctx, raw); err != nil {
				t.Errorf("unset, typ %q was refused: %v", typ, err)
			}
		}
	}
	// Another type entirely, for something an issuer signs that is not a
	// token at all, is taken only where it is asked for.
	list := sign(t, p.rsaPEM(t), "RS256", claims(p, nil), map[string]any{"kid": "rsa-1", "typ": "wireguard-peers+jwt"})
	mustRefuse(t, lax, list, "type")
	if _, err := verifier(t, p, oidc.Config{Type: "wireguard-peers+jwt"}).Verify(ctx, list); err != nil {
		t.Errorf("the asked-for type was refused: %v", err)
	}
}
