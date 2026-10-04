package oidc

import (
	"context"
	"crypto/tls"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// ⛔ New refuses an http:// JWKS URL, and an https one that REDIRECTS to http
// must be refused the same way: the key set decides every signature. Before
// v0.2.4 the default client followed the redirect and took the keys over
// cleartext (security audit). A caller's own client, which may follow
// anything, is caught after the fetch by the URL of the last request.
func TestAKeySetBehindARedirectToCleartextIsRefused(t *testing.T) {
	var cleartextHits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cleartextHits.Add(1)
		w.Write([]byte(`{"keys":[{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}]}`))
	}))
	defer plain.Close()
	tlsSrv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/loop" {
			http.Redirect(w, r, "https://issuer.example/loop", http.StatusFound)
			return
		}
		http.Redirect(w, r, "http://keys.attacker.test/jwks.json", http.StatusFound)
	}))
	defer tlsSrv.Close()
	// Route every host name to the two local servers (stands in for DNS / the network path).
	old := http.DefaultTransport
	defer func() { http.DefaultTransport = old }()
	http.DefaultTransport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // test CA only; the https leg is not what is under test
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if _, port, _ := net.SplitHostPort(addr); port == "443" {
				return net.Dial(network, tlsSrv.Listener.Addr().String())
			}
			return net.Dial(network, plain.Listener.Addr().String())
		},
	}
	_, err := New(context.Background(), Config{Issuer: "https://issuer.example", Audience: "app", JWKSURL: "https://issuer.example/jwks"})
	if err == nil {
		t.Error("the default client took the key set from http://keys.attacker.test after a redirect")
	}
	if n := cleartextHits.Load(); n != 0 {
		t.Errorf("the default client still made %d cleartext request(s)", n)
	}
	// The CheckRedirect that refuses http also keeps net/http's limit on hops.
	_, err = New(context.Background(), Config{Issuer: "https://issuer.example", Audience: "app", JWKSURL: "https://issuer.example/loop"})
	if err == nil || !strings.Contains(err.Error(), "redirects") {
		t.Errorf("a redirect loop gave %v", err)
	}
	// A caller's own client follows the redirect; the keys must still be refused.
	_, err = New(context.Background(), Config{Issuer: "https://issuer.example", Audience: "app",
		JWKSURL: "https://issuer.example/jwks", Client: &http.Client{}})
	if err == nil {
		t.Error("a caller's client took the key set from http://keys.attacker.test after a redirect")
	}
}
