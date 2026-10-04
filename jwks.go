// SPDX-License-Identifier: BSD-3-Clause

package oidc

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// errBadSignature is what a signature that does not check says. It is one
// error for every algorithm, because the difference is a fact about the key
// and telling somebody who sent a forged token which part failed helps only
// them.
var errBadSignature = errors.New("oidc: the signature does not check")

// A keySet is the issuer's published keys, and the rule for asking again.
type keySet struct {
	url    string
	client *http.Client

	// MinRefresh is how long to wait before fetching again after a key was
	// not found. Without it, a token carrying a kid nobody has is a request
	// to the issuer for every attempt -- which is somebody else's server,
	// hit as fast as an attacker can send.
	minRefresh time.Duration

	mu      sync.Mutex
	keys    map[string]any
	untyped []any // keys published without a kid

	// asked is when the last fetch FINISHED, whether it succeeded or not.
	// The window is counted from attempts rather than successes: counted from
	// successes, an issuer whose key set is failing is asked once per forged
	// token for exactly as long as it is failing.
	asked time.Time
	// inflight is the fetch under way, if there is one. A request that needs
	// the key set while it runs waits for its answer instead of asking again.
	inflight *inflight
}

// An inflight fetch, which any number of requests can wait for.
type inflight struct {
	done chan struct{}
	err  error // read only after done is closed
}

// check verifies a signature, fetching the key set again if what is held
// cannot verify it.
//
// Two things make a held key set insufficient, and they need the same answer:
// a kid nobody has, and a kid whose KEY CHANGED. The second one is not
// hypothetical -- a provider that rotates without changing the kid is doing
// something inadvisable and something several of them do -- and a verifier
// that only refetched on an unknown kid would refuse every token from the
// moment of the roll until it restarted.
//
// Both are bounded by minRefresh: a forged token cannot make this server ask
// the issuer for keys as fast as it can send. The bound is on ATTEMPTS, so it
// holds while the issuer is failing too, and it holds for requests that arrive
// together: the ones that arrive while a fetch is in flight share its answer.
func (k *keySet) check(ctx context.Context, header joseHeader, signed, signature []byte) error {
	if err := k.tryHeld(header, signed, signature); err == nil {
		return nil
	}
	if err := k.refresh(ctx, header.Kid); err != nil {
		return err
	}
	if err := k.tryHeld(header, signed, signature); err != nil {
		if header.Kid != "" && !k.has(header.Kid) {
			return fmt.Errorf("oidc: the issuer publishes no key %q", header.Kid)
		}
		return errBadSignature
	}
	return nil
}

// refresh fetches the key set again if minRefresh allows it, or waits for the
// fetch already under way.
//
// The fetch runs on its own, detached from the caller's cancellation: it is
// shared, and one caller giving up must not hand every other one an error.
// Each caller still stops waiting when its own context ends. The HTTP client's
// timeout bounds the fetch itself.
func (k *keySet) refresh(ctx context.Context, kid string) error {
	k.mu.Lock()
	f := k.inflight
	if f == nil {
		if since := time.Since(k.asked); since < k.minRefresh {
			k.mu.Unlock()
			if kid != "" {
				return fmt.Errorf("oidc: no key %q verifies this, and the key set was asked for %s ago",
					kid, since.Round(time.Second))
			}
			return errBadSignature
		}
		f = &inflight{done: make(chan struct{})}
		k.inflight = f
		go k.fetchFor(context.WithoutCancel(ctx), f)
	}
	k.mu.Unlock()
	select {
	case <-f.done:
		return f.err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// fetchFor runs one shared fetch and tells everybody waiting for it.
func (k *keySet) fetchFor(ctx context.Context, f *inflight) {
	err := k.fetch(ctx) // records asked before the slot is freed
	k.mu.Lock()
	k.inflight = nil
	k.mu.Unlock()
	f.err = err
	close(f.done)
}

// tryHeld verifies against what is held now.
//
// Every candidate key is tried and the loop does not stop at the first
// failure: a set holding two keys without kids is legitimate, and the answer
// must not depend on map order.
func (k *keySet) tryHeld(header joseHeader, signed, signature []byte) error {
	k.mu.Lock()
	keys, ok := k.lookupLocked(header.Kid)
	k.mu.Unlock()
	if !ok {
		return errBadSignature
	}
	for _, key := range keys {
		if err := verifySignature(header.Alg, key, signed, signature); err == nil {
			return nil
		}
	}
	return errBadSignature
}

// has reports whether a kid is published at all, which separates "no such
// key" from "that signature is wrong".
func (k *keySet) has(kid string) bool {
	k.mu.Lock()
	defer k.mu.Unlock()
	_, ok := k.keys[kid]
	return ok
}

// lookupLocked answers with the keys worth trying for a kid.
func (k *keySet) lookupLocked(kid string) ([]any, bool) {
	if kid != "" {
		if key, ok := k.keys[kid]; ok {
			return []any{key}, true
		}
		// A token naming a kid the set does not have is not answered by
		// trying the others: the issuer said which key, and a signature that
		// checks under a different one is a coincidence worth refusing.
		return nil, false
	}
	// No kid: every key is a candidate, which is what an issuer publishing a
	// single key without one intends. Signature verification decides.
	var all []any
	all = append(all, k.untyped...)
	for _, key := range k.keys {
		all = append(all, key)
	}
	return all, len(all) > 0
}

// fetch reads the key set, and records that it asked whatever the answer.
func (k *keySet) fetch(ctx context.Context) error {
	defer func() {
		k.mu.Lock()
		k.asked = time.Now()
		k.mu.Unlock()
	}()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, k.url, nil)
	if err != nil {
		return err
	}
	res, err := k.client.Do(req)
	if err != nil {
		return fmt.Errorf("oidc: reading the key set: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return fmt.Errorf("oidc: the key set at %s answered %s", k.url, res.Status)
	}
	var doc struct {
		Keys []jwk `json:"keys"`
	}
	if err := json.NewDecoder(limit(res.Body)).Decode(&doc); err != nil {
		return fmt.Errorf("oidc: the key set is not JSON: %w", err)
	}
	keys := map[string]any{}
	var untyped []any
	for _, j := range doc.Keys {
		// A key published for encryption is not a key to check signatures
		// with, and a key set legitimately holds both.
		if j.Use != "" && j.Use != "sig" {
			continue
		}
		key, err := j.parse()
		if err != nil {
			// One unreadable key does not spoil the set: an issuer that adds
			// a kind this package does not know should not take a server
			// down. What it must not do is silently become a set with no
			// keys, which the caller finds out at the first token.
			continue
		}
		if j.Kid == "" {
			untyped = append(untyped, key)
			continue
		}
		keys[j.Kid] = key
	}
	if len(keys) == 0 && len(untyped) == 0 {
		return fmt.Errorf("oidc: %s published no key this can read", k.url)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	k.keys, k.untyped = keys, untyped
	return nil
}

// A jwk is one published key (RFC 7517).
type jwk struct {
	Kty string `json:"kty"`
	Kid string `json:"kid"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	N   string `json:"n"`
	E   string `json:"e"`
	Crv string `json:"crv"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// parse turns it into a key crypto can use.
func (j jwk) parse() (any, error) {
	switch j.Kty {
	case "RSA":
		n, err := decode(j.N)
		if err != nil {
			return nil, err
		}
		e, err := decode(j.E)
		if err != nil {
			return nil, err
		}
		if len(n) < 256 {
			// 2048 bits is the floor RFC 7518 §3.3 sets for RS256, and a
			// short key is not a small inconvenience: it is a signature
			// somebody else can produce.
			return nil, fmt.Errorf("oidc: an RSA key of %d bits", len(n)*8)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(n), E: int(new(big.Int).SetBytes(e).Int64())}, nil
	case "EC":
		curve, size, err := curveFor(j.Crv)
		if err != nil {
			return nil, err
		}
		x, err := decode(j.X)
		if err != nil {
			return nil, err
		}
		y, err := decode(j.Y)
		if err != nil {
			return nil, err
		}
		if len(x) != size || len(y) != size {
			return nil, fmt.Errorf("oidc: a %s point of %d and %d bytes", j.Crv, len(x), len(y))
		}
		key := &ecdsa.PublicKey{Curve: curve, X: new(big.Int).SetBytes(x), Y: new(big.Int).SetBytes(y)}
		if !curve.IsOnCurve(key.X, key.Y) {
			// A point that is not on the curve is not a key. Some
			// implementations have been persuaded to do arithmetic with one.
			return nil, fmt.Errorf("oidc: a %s point that is not on the curve", j.Crv)
		}
		return key, nil
	case "OKP":
		if j.Crv != "Ed25519" {
			return nil, fmt.Errorf("oidc: an OKP key on %q", j.Crv)
		}
		x, err := decode(j.X)
		if err != nil {
			return nil, err
		}
		if len(x) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("oidc: an Ed25519 key of %d bytes", len(x))
		}
		return ed25519.PublicKey(x), nil
	}
	return nil, fmt.Errorf("oidc: a key of kind %q", j.Kty)
}

func curveFor(name string) (elliptic.Curve, int, error) {
	switch name {
	case "P-256":
		return elliptic.P256(), 32, nil
	case "P-384":
		return elliptic.P384(), 48, nil
	case "P-521":
		return elliptic.P521(), 66, nil
	}
	return nil, 0, fmt.Errorf("oidc: a key on curve %q", name)
}

// httpsOrLoopback refuses to fetch what decides every signature over a link
// somebody can rewrite.
//
// Loopback is exempt because there is no link: a test issuer, or a provider
// on the same machine behind something else's TLS.
func httpsOrLoopback(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("oidc: %q is not a URL", raw)
	}
	if u.Scheme == "https" {
		return nil
	}
	if u.Scheme == "http" && loopbackHost(u.Hostname()) {
		return nil
	}
	return fmt.Errorf("oidc: %s is not https: the key set decides every signature, "+
		"and over cleartext so does anybody on the way", raw)
}

func loopbackHost(host string) bool {
	if host == "localhost" || strings.HasSuffix(host, ".localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
