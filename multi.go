// SPDX-License-Identifier: BSD-3-Clause

package oidc

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

// Issuer is the "iss" this verifier requires, exactly (trailing slashes
// removed, as discovery does).
func (v *Verifier) Issuer() string { return v.cfg.Issuer }

// MaxTokenSize bounds the compact token a [Set] reads the issuer of: a token
// longer than this is refused before any decoding.
const MaxTokenSize = 16 << 10

// ErrUnknownIssuer is a token whose "iss" no verifier of the set is
// configured for (or that carries none readable).
var ErrUnknownIssuer = errors.New("oidc: the token's issuer is not one this service accepts")

// A Set verifies tokens from several issuers, each with its own audience and
// key set.
//
// The token is routed by its UNVERIFIED "iss" to the one verifier configured
// for exactly that issuer, and verified there: signature against that issuer's
// keys, "iss" again by exact comparison, audience, times. Reading "iss" first
// chooses which key set to use and nothing else, so it grants nothing: a
// forged token fails the verification that follows. What it must never do is
// try every key set -- one issuer's key could then vouch for another issuer's
// name -- or fetch anything for an issuer nobody configured: an unknown issuer
// costs no network access at all.
//
// With a single verifier there is nothing to route: the token goes straight to
// it and its own exact "iss" check refuses a stranger, at no extra cost.
type Set struct {
	vs []*Verifier
}

// NewSet is the set of verifiers. Two verifiers for one issuer are refused: a
// token could not be routed to either of them.
func NewSet(vs ...*Verifier) (*Set, error) {
	seen := map[string]bool{}
	for _, v := range vs {
		if v == nil {
			return nil, errors.New("oidc: a nil verifier in the set")
		}
		if seen[v.Issuer()] {
			return nil, fmt.Errorf("oidc: two verifiers for issuer %q: a token could not be routed", v.Issuer())
		}
		seen[v.Issuer()] = true
	}
	return &Set{vs: append([]*Verifier(nil), vs...)}, nil
}

// Len is the number of verifiers.
func (s *Set) Len() int { return len(s.vs) }

// For returns the verifier a token is routed to, or [ErrUnknownIssuer].
func (s *Set) For(raw string) (*Verifier, error) {
	if len(s.vs) == 1 {
		return s.vs[0], nil
	}
	iss, ok := PeekIssuer(raw)
	if !ok {
		return nil, ErrUnknownIssuer
	}
	iss = strings.TrimRight(iss, "/")
	for _, v := range s.vs {
		if v.Issuer() == iss {
			return v, nil
		}
	}
	return nil, ErrUnknownIssuer
}

// Verify routes the token and verifies it. The verifier that did is the one
// [Set.For] returns for the same token.
func (s *Set) Verify(ctx context.Context, raw string) (*Token, error) {
	v, err := s.For(raw)
	if err != nil {
		return nil, err
	}
	return v.Verify(ctx, raw)
}

// PeekIssuer reads "iss" from the payload of a compact JWT without verifying
// anything. Use it to choose a key set, never to trust the token. It reports
// false for a token over [MaxTokenSize], one that is not three dot-separated
// segments, a payload that is not base64url JSON, or an "iss" that is not a
// non-empty string.
func PeekIssuer(raw string) (string, bool) {
	if len(raw) > MaxTokenSize {
		return "", false
	}
	i := strings.IndexByte(raw, '.')
	if i < 0 {
		return "", false
	}
	rest := raw[i+1:]
	j := strings.IndexByte(rest, '.')
	if j < 0 || strings.IndexByte(rest[j+1:], '.') >= 0 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(rest[:j])
	if err != nil {
		return "", false
	}
	var c struct {
		Iss string `json:"iss"`
	}
	if json.Unmarshal(payload, &c) != nil || c.Iss == "" {
		return "", false
	}
	return c.Iss, true
}
