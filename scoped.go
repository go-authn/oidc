// SPDX-License-Identifier: BSD-3-Clause

package oidc

import (
	"errors"
	"strings"
)

// Scoped names.
//
// An account is relative to an institution: "alice" at one university is not
// "alice" at another, and a federation proxy (eduGAIN through MyAccessID,
// eduTEAMS, Renater, a Keycloak broker) puts people of many institutions
// behind one issuer. The names federations use for a person carry that
// institution as a scope, "local@scope": eduPersonPrincipalName (claim
// eduperson_principal_name; eduPerson schema: single-valued, EQUALITY
// caseIgnoreMatch) is "user@scope" with the scope the administrative domain
// that issued it (SWITCH's definition), voperson_id and the scoped
// affiliations are the same shape.
//
// A scope in a token is the issuer's assertion, so it is checked as
// Shibboleth checks a scope: it is accepted only when the issuer may assert it.
// [ScopedName] does that check, against the scopes the service allows for this
// issuer: its own domains, or the institutions of a federation it serves.
//
// Names are compared as the schema compares them (caseIgnoreMatch), so the
// result is ASCII-lower-cased (not Unicode: U+212A is not a "k").

// ErrNoScope is a name that carries no scope and for which no default scope was
// given: it is not an identity.
var ErrNoScope = errors.New("oidc: the name carries no scope (want local@scope)")

// ErrScopeNotAllowed is a name whose scope the issuer may not assert.
var ErrScopeNotAllowed = errors.New("oidc: the name's scope is not one this issuer may assert")

// ErrBadName is a name that is not a well-formed local@scope.
var ErrBadName = errors.New("oidc: the name is not a well-formed local@scope")

const (
	maxLocal = 128
	maxScope = 253 // RFC 1035: a domain name
)

// ScopedName returns the person's name as "local@scope", ASCII-lower-cased,
// after checking the scope against allowed (compared as [Normalize] does for
// the schac_home_organization claim: ASCII case folded, one trailing dot
// dropped).
//
// A name without "@" takes defaultScope when it is not empty (the scope of an
// institution whose accounts predate scoped names: "alice" at
// "polytechnique.edu" is "alice@polytechnique.edu"), and is [ErrNoScope]
// otherwise. A defaultScope must itself be allowed. More than one "@" is
// [ErrBadName]: the rule is exactly one local@scope, so that a consumer that
// splits at the first "@" and one that splits at the last read the same scope.
// An empty local part or scope, a control
// character, a space, or a name over the bounds is [ErrBadName]; a scope that
// is not in allowed is [ErrScopeNotAllowed]. An empty allowed list allows no
// scope.
func ScopedName(name string, allowed []string, defaultScope string) (string, error) {
	if len(name) > maxLocal+1+maxScope {
		return "", ErrBadName
	}
	if strings.Count(name, "@") > 1 {
		return "", ErrBadName
	}
	local, scope, ok := cutLast(name, '@')
	if !ok {
		if defaultScope == "" {
			return "", ErrNoScope
		}
		local, scope = name, defaultScope
	}
	scope = asciiLower(strings.TrimSuffix(scope, "."))
	local = asciiLower(local)
	if local == "" || scope == "" || len(local) > maxLocal || len(scope) > maxScope || badRunes(local) || badRunes(scope) || strings.ContainsRune(scope, '@') {
		return "", ErrBadName
	}
	for _, a := range allowed {
		if asciiLower(strings.TrimSuffix(a, ".")) == scope {
			return local + "@" + scope, nil
		}
	}
	return "", ErrScopeNotAllowed
}

// ScopedUsername is [ScopedName] of [Token.Username]: configure the claim that
// carries the scoped name (UsernameClaim "eduperson_principal_name") or take
// the default fallbacks and a defaultScope for unscoped ones.
func (t *Token) ScopedUsername(allowed []string, defaultScope string) (string, error) {
	return ScopedName(t.Username(), allowed, defaultScope)
}

func cutLast(s string, sep byte) (before, after string, ok bool) {
	if i := strings.LastIndexByte(s, sep); i >= 0 {
		return s[:i], s[i+1:], true
	}
	return s, "", false
}

func badRunes(s string) bool {
	for _, r := range s {
		if r <= 0x20 || r == 0x7f || r == ' ' || r == ' ' {
			return true
		}
	}
	return false
}
