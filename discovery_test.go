package oidc_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-authn/oidc"
)

// Discovery reads the two documents, and refuses what cannot be trusted.
func TestDiscovery(t *testing.T) {
	ctx := context.Background()

	t.Run("a provider that is not answering", func(t *testing.T) {
		// A verifier is built at startup for this reason: a provider that is
		// down is a server that cannot authenticate anybody, and it should
		// say so before it listens.
		_, err := oidc.New(ctx, oidc.Config{Issuer: "http://127.0.0.1:1", Audience: "fileshare"})
		if err == nil {
			t.Fatal("a provider nothing is listening on was accepted")
		}
	})

	t.Run("a document naming another issuer", func(t *testing.T) {
		// ⛔ Otherwise tokens are checked against keys belonging to somebody
		// the caller never named.
		p := newProvider(t)
		p.issuerInDoc = "https://somebody.else.test"
		_, err := oidc.New(ctx, oidc.Config{Issuer: p.URL, Audience: "fileshare"})
		if err == nil || !strings.Contains(err.Error(), "says its issuer is") {
			t.Errorf("error = %v", err)
		}
	})

	t.Run("a document with no jwks_uri", func(t *testing.T) {
		p := newProvider(t)
		p.omitJWKS = true
		_, err := oidc.New(ctx, oidc.Config{Issuer: p.URL, Audience: "fileshare"})
		if err == nil || !strings.Contains(err.Error(), "no jwks_uri") {
			t.Errorf("error = %v", err)
		}
	})

	t.Run("a key set with nothing readable in it", func(t *testing.T) {
		p := newProvider(t)
		p.keysBody = `{"keys":[{"kty":"OCT","kid":"x"}]}`
		_, err := oidc.New(ctx, oidc.Config{Issuer: p.URL, Audience: "fileshare"})
		if err == nil || !strings.Contains(err.Error(), "no key this can read") {
			t.Errorf("error = %v", err)
		}
	})

	t.Run("a jwks_uri given directly", func(t *testing.T) {
		// For a provider that publishes no discovery document, or one behind
		// something that does not forward it.
		p := newProvider(t)
		v, err := oidc.New(ctx, oidc.Config{Issuer: p.URL, Audience: "fileshare", JWKSURL: p.URL + "/keys"})
		if err != nil {
			t.Fatal(err)
		}
		raw := sign(t, p.rsaPEM(t), "RS256", claims(p, nil), map[string]any{"kid": "rsa-1"})
		if _, err := v.Verify(ctx, raw); err != nil {
			t.Errorf("a token was refused: %v", err)
		}
	})
}

// ⛔ What decides every signature is not fetched over a link somebody can
// rewrite.
func TestKeysAreNotFetchedOverCleartext(t *testing.T) {
	ctx := context.Background()
	_, err := oidc.New(ctx, oidc.Config{Issuer: "http://login.example.org", Audience: "fileshare"})
	if err == nil || !strings.Contains(err.Error(), "not https") {
		t.Errorf("an http issuer gave %v", err)
	}
	// A jwks_uri that leaves the machine is refused even when the issuer did
	// not: the key set is the thing that matters.
	p := newProvider(t)
	_, err = oidc.New(ctx, oidc.Config{Issuer: p.URL, Audience: "fileshare", JWKSURL: "http://keys.example.org/jwks"})
	if err == nil || !strings.Contains(err.Error(), "not https") {
		t.Errorf("an http key set gave %v", err)
	}
	// Loopback is exempt, because there is no link to intercept -- which is
	// what every test here relies on.
	if _, err := oidc.New(ctx, oidc.Config{Issuer: p.URL, Audience: "fileshare"}); err != nil {
		t.Errorf("a loopback provider was refused: %v", err)
	}
}

// A configuration that cannot verify anything is refused rather than built.
func TestConfigurationsThatAcceptEverybody(t *testing.T) {
	ctx := context.Background()
	if _, err := oidc.New(ctx, oidc.Config{Audience: "fileshare"}); err == nil {
		t.Error("a verifier with no issuer was built")
	}
	p := newProvider(t)
	_, err := oidc.New(ctx, oidc.Config{Issuer: p.URL})
	if err == nil || !strings.Contains(err.Error(), "no audience") {
		t.Errorf("a verifier with no audience gave %v", err)
	}
}

// ⛔ Keys rotate, so an unknown kid is worth one fetch -- and a token carrying
// a kid nobody has must not be a way to make this server hammer the issuer.
func TestKeyRotationAndTheRefetchLimit(t *testing.T) {
	ctx := context.Background()
	var fetches atomic.Int64
	old := newProvider(t)
	next := newProvider(t)
	current := old

	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": issuerOf(r), "jwks_uri": issuerOf(r) + "/keys"})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{current.rsaJWK()}})
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	v, err := oidc.New(ctx, oidc.Config{
		Issuer: srv.URL, Audience: "fileshare", MinRefresh: 50 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	at := fetches.Load()

	// A token from the key the provider has: no refetch.
	raw := sign(t, old.rsaPEM(t), "RS256", claims(providerAt(old, srv.URL), nil), map[string]any{"kid": "rsa-1"})
	if _, err := v.Verify(ctx, raw); err != nil {
		t.Fatalf("a token signed by the published key was refused: %v", err)
	}
	if fetches.Load() != at {
		t.Error("a key the verifier already had was fetched again")
	}

	// A kid nobody has: one fetch, then no more until MinRefresh passes.
	unknown := sign(t, old.rsaPEM(t), "RS256", claims(providerAt(old, srv.URL), nil), map[string]any{"kid": "rsa-99"})
	for range 5 {
		v.Verify(ctx, unknown)
	}
	if got := fetches.Load() - at; got != 1 {
		t.Errorf("%d fetches for five tokens with an unknown kid, want 1", got)
	}

	// The provider rotates. After MinRefresh, the new key is picked up --
	// without which this server stops working the day the issuer rolls a key.
	current = next
	time.Sleep(60 * time.Millisecond)
	rotated := sign(t, next.rsaPEM(t), "RS256", claims(providerAt(next, srv.URL), nil), map[string]any{"kid": "rsa-1"})
	if _, err := v.Verify(ctx, rotated); err != nil {
		t.Errorf("a token signed by the rotated key was refused: %v", err)
	}
}

// A key set endpoint that counts, can be made to fail, and can be held open,
// so a test can say exactly how many times the verifier asked.
type countingKeys struct {
	*httptest.Server
	fetches atomic.Int64
	failing atomic.Bool
	// hold, when set, keeps every fetch open until it is closed.
	hold    atomic.Pointer[chan struct{}]
	current atomic.Pointer[provider]
}

func newCountingKeys(t *testing.T, p *provider) *countingKeys {
	t.Helper()
	c := &countingKeys{}
	c.current.Store(p)
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"issuer": issuerOf(r), "jwks_uri": issuerOf(r) + "/keys"})
	})
	mux.HandleFunc("/keys", func(w http.ResponseWriter, r *http.Request) {
		c.fetches.Add(1)
		if hold := c.hold.Load(); hold != nil {
			<-*hold
		}
		if c.failing.Load() {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"keys": []any{c.current.Load().rsaJWK()}})
	})
	c.Server = httptest.NewServer(mux)
	t.Cleanup(c.Close)
	return c
}

// ⛔ Two hundred tokens with a kid nobody has, all at once, are ONE question
// to the issuer. The bound is one fetch per MinRefresh, and a bound that holds
// only for requests arriving one after another is not one: the requests that
// arrive while a fetch is in flight wait for its answer instead of asking
// again.
func TestConcurrentUnknownKidsShareOneFetch(t *testing.T) {
	ctx := context.Background()
	p := newProvider(t)
	keys := newCountingKeys(t, p)
	v, err := oidc.New(ctx, oidc.Config{
		Issuer: keys.URL, Audience: "fileshare", MinRefresh: 200 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	unknown := sign(t, p.rsaPEM(t), "RS256", claims(providerAt(p, keys.URL), nil), map[string]any{"kid": "rsa-99"})
	time.Sleep(250 * time.Millisecond)
	at := keys.fetches.Load()

	hold := make(chan struct{})
	keys.hold.Store(&hold)
	var wg sync.WaitGroup
	for range 200 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := v.Verify(ctx, unknown); err == nil {
				t.Error("a token with an unknown kid was accepted")
			}
		}()
	}
	for keys.fetches.Load() == at {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(50 * time.Millisecond) // the rest are queued behind it by now

	// A caller that gives up while the fetch is in flight is answered at once,
	// not when the issuer gets round to it.
	gone, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := v.Verify(gone, unknown); !errors.Is(err, context.Canceled) {
		t.Errorf("a caller that gave up while a fetch was in flight got %v", err)
	}

	keys.hold.Store(nil)
	close(hold)
	wg.Wait()
	if got := keys.fetches.Load() - at; got != 1 {
		t.Errorf("%d fetches for 200 concurrent tokens with an unknown kid, want 1", got)
	}
}

// ⛔ An issuer whose key set is DOWN is still asked at most once per
// MinRefresh. Counting only the fetches that succeeded would let every forged
// token through to the issuer for exactly as long as it is failing -- which is
// when it can least afford it. And once it is back, a rotated key is still
// picked up after MinRefresh.
func TestAFailingKeySetIsNotAskedFasterThanMinRefresh(t *testing.T) {
	ctx := context.Background()
	old := newProvider(t)
	next := newProvider(t)
	keys := newCountingKeys(t, old)
	v, err := oidc.New(ctx, oidc.Config{
		Issuer: keys.URL, Audience: "fileshare", MinRefresh: 100 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	unknown := sign(t, old.rsaPEM(t), "RS256", claims(providerAt(old, keys.URL), nil), map[string]any{"kid": "rsa-99"})
	time.Sleep(120 * time.Millisecond)
	keys.failing.Store(true)
	at := keys.fetches.Load()

	_, err = v.Verify(ctx, unknown)
	if err == nil || !strings.Contains(err.Error(), "answered 500") {
		t.Errorf("the first token after the issuer failed gave %v, want its error", err)
	}
	for range 100 {
		if _, err := v.Verify(ctx, unknown); err == nil {
			t.Fatal("a token with an unknown kid was accepted")
		}
	}
	if got := keys.fetches.Load() - at; got != 1 {
		t.Errorf("%d fetches for 101 tokens while the key set was failing, want 1", got)
	}

	// The issuer comes back, having rotated.
	keys.failing.Store(false)
	keys.current.Store(next)
	time.Sleep(120 * time.Millisecond)
	rotated := sign(t, next.rsaPEM(t), "RS256", claims(providerAt(next, keys.URL), nil), map[string]any{"kid": "rsa-1"})
	if _, err := v.Verify(ctx, rotated); err != nil {
		t.Errorf("a token signed by the rotated key was refused after the issuer recovered: %v", err)
	}
}

// issuerOf is the URL a request arrived at, which is what the fixture calls
// itself.
func issuerOf(r *http.Request) string { return "http://" + r.Host }

// providerAt is a provider whose tokens claim to come from another URL.
func providerAt(p *provider, url string) *provider {
	clone := *p
	clone.Server = nil
	clone.url = url
	return &clone
}
