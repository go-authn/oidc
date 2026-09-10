// SPDX-License-Identifier: BSD-3-Clause

package oidc

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Config is what a verifier needs to know. Issuer and Audience are required:
// a verifier without them is one that accepts every token anybody ever signed.
type Config struct {
	// Issuer is the "iss" a token must carry, exactly. It is also where
	// discovery starts, unless JWKSURL is given.
	Issuer string
	// Audience is the "aud" a token must be addressed to -- this service's
	// client id at the provider.
	Audience string

	// JWKSURL skips discovery, for a provider that does not publish
	// /.well-known/openid-configuration or one behind something that does not
	// forward it.
	JWKSURL string

	// UsernameClaim is which claim names the person. Default
	// "preferred_username", falling back to "email" and then "sub" -- see
	// [Token.Username], where the fallback is explained.
	UsernameClaim string
	// GroupsClaim is which claim carries their groups. Default "groups".
	GroupsClaim string

	// ClockSkew is how much a clock may differ before a token is early or
	// late. Default one minute; a provider and a server that disagree by more
	// than that have a problem worth fixing rather than tolerating.
	ClockSkew time.Duration
	// MinRefresh is how long to wait before fetching the key set again after
	// a key was not found. Default one minute: keys rotate, and a token with
	// an unknown kid must not be a way to make this server hammer the
	// issuer.
	MinRefresh time.Duration

	// Client is the HTTP client for discovery and the key set. A caller with
	// a proxy, a private CA or a timeout of its own passes one.
	Client *http.Client
	// Now overrides the clock, for tests.
	Now func() time.Time
}

// A Verifier checks tokens from one issuer for one audience.
//
// It is safe for concurrent use, and it holds the key set: build one at
// startup and keep it, rather than one per request.
type Verifier struct {
	cfg  Config
	keys *keySet

	mu sync.Mutex
}

// New reads the provider's configuration and prepares to verify.
//
// Discovery happens HERE rather than at the first token, for the same reason a
// database is pinged at startup: a provider that is not answering is a server
// that cannot authenticate anybody, and it should say so before it listens.
func New(ctx context.Context, cfg Config) (*Verifier, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("oidc: no issuer: a verifier without one accepts tokens from anybody")
	}
	if cfg.Audience == "" {
		return nil, fmt.Errorf("oidc: no audience: a token minted for another service is a valid token, " +
			"and a verifier that does not check accepts every one the issuer ever signed")
	}
	if err := httpsOrLoopback(cfg.Issuer); err != nil {
		return nil, err
	}
	cfg.Issuer = strings.TrimRight(cfg.Issuer, "/")
	if cfg.Client == nil {
		cfg.Client = &http.Client{Timeout: 30 * time.Second}
	}
	if cfg.ClockSkew == 0 {
		cfg.ClockSkew = time.Minute
	}
	if cfg.MinRefresh == 0 {
		cfg.MinRefresh = time.Minute
	}
	v := &Verifier{cfg: cfg}

	jwks := cfg.JWKSURL
	if jwks == "" {
		var err error
		if jwks, err = v.discover(ctx); err != nil {
			return nil, err
		}
	}
	if err := httpsOrLoopback(jwks); err != nil {
		return nil, err
	}
	v.keys = &keySet{url: jwks, client: cfg.Client, minRefresh: cfg.MinRefresh}
	if err := v.keys.fetch(ctx); err != nil {
		return nil, err
	}
	return v, nil
}

// discover reads /.well-known/openid-configuration.
func (v *Verifier) discover(ctx context.Context) (string, error) {
	url := v.cfg.Issuer + "/.well-known/openid-configuration"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", err
	}
	res, err := v.cfg.Client.Do(req)
	if err != nil {
		return "", fmt.Errorf("oidc: reading %s: %w", url, err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", fmt.Errorf("oidc: %s answered %s", url, res.Status)
	}
	var doc struct {
		Issuer  string `json:"issuer"`
		JWKSURL string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(limit(res.Body)).Decode(&doc); err != nil {
		return "", fmt.Errorf("oidc: %s is not JSON: %w", url, err)
	}
	// ⛔ The document says who it is for, and it must be who we asked. A
	// provider whose configuration names a different issuer is either
	// misconfigured or somebody else's, and tokens from it would then be
	// checked against the wrong issuer's keys.
	if strings.TrimRight(doc.Issuer, "/") != v.cfg.Issuer {
		return "", fmt.Errorf("oidc: %s says its issuer is %q, and we asked %q", url, doc.Issuer, v.cfg.Issuer)
	}
	if doc.JWKSURL == "" {
		return "", fmt.Errorf("oidc: %s names no jwks_uri", url)
	}
	return doc.JWKSURL, nil
}

// Verify checks a token and says who it is about.
//
// Everything that can be wrong with a token is one error to the caller, and
// the detail is for a server's own log: a client that sent a token it should
// not have is not owed an explanation of which check caught it.
func (v *Verifier) Verify(ctx context.Context, raw string) (*Token, error) {
	header, payload, signed, signature, err := split(strings.TrimSpace(raw))
	if err != nil {
		return nil, err
	}
	// ⛔ alg: none, and every algorithm the issuer did not publish. A token
	// that says it is unsigned is a JSON object somebody typed; an HMAC one
	// verified against a PUBLIC key is a token anybody can mint.
	if !signatureAlgorithms[header.Alg] {
		return nil, fmt.Errorf("oidc: this does not accept %q signatures", header.Alg)
	}
	if header.Typ != "" && !strings.EqualFold(header.Typ, "JWT") && !strings.EqualFold(header.Typ, "at+jwt") {
		return nil, fmt.Errorf("oidc: a token of type %q", header.Typ)
	}
	if err := v.keys.check(ctx, header, signed, signature); err != nil {
		return nil, err
	}

	var tok Token
	if err := json.Unmarshal(payload, &tok.claims); err != nil {
		return nil, fmt.Errorf("oidc: the payload is not JSON: %w", err)
	}
	if err := v.check(&tok); err != nil {
		return nil, err
	}
	tok.usernameClaim, tok.groupsClaim = v.cfg.UsernameClaim, v.cfg.GroupsClaim
	return &tok, nil
}

// check is everything that is true of a token this server should accept,
// after the signature.
func (v *Verifier) check(tok *Token) error {
	// ⛔ Compared WHOLE. https://login.example.org.evil.test starts with the
	// right string, and a prefix test is how a verifier ends up trusting it.
	if subtle.ConstantTimeCompare([]byte(strings.TrimRight(tok.Issuer(), "/")), []byte(v.cfg.Issuer)) != 1 {
		return fmt.Errorf("oidc: the token is from %q and this accepts %q", tok.Issuer(), v.cfg.Issuer)
	}
	if !tok.forAudience(v.cfg.Audience) {
		return fmt.Errorf("oidc: the token is addressed to %v and this is %q", tok.Audience(), v.cfg.Audience)
	}
	now := v.now()
	exp, ok := tok.Expiry()
	if !ok {
		// A token with no expiry never stops being valid, which is not a
		// token: it is a password somebody can copy once.
		return fmt.Errorf("oidc: the token has no expiry")
	}
	if now.After(exp.Add(v.cfg.ClockSkew)) {
		return fmt.Errorf("oidc: the token expired %s ago", now.Sub(exp).Round(time.Second))
	}
	if nbf, ok := tok.NotBefore(); ok && now.Add(v.cfg.ClockSkew).Before(nbf) {
		return fmt.Errorf("oidc: the token is not valid for another %s", nbf.Sub(now).Round(time.Second))
	}
	return nil
}

func (v *Verifier) now() time.Time {
	if v.cfg.Now != nil {
		return v.cfg.Now()
	}
	return time.Now()
}

// limit caps what a provider can make this process read. A document that is
// megabytes long is not a configuration; it is a way to spend somebody's
// memory.
func limit(r io.Reader) io.Reader { return io.LimitReader(r, 1<<20) }
