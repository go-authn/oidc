// SPDX-License-Identifier: BSD-3-Clause

package oidc

import (
	"encoding/json"
	"fmt"
	"time"
)

// A Token is a verified token: what the issuer said about who is asking.
//
// Every method reads the claims that arrived. Nothing here re-checks anything
// -- a Token exists only because [Verifier.Verify] returned it -- and nothing
// here reaches the network.
type Token struct {
	claims map[string]json.RawMessage

	usernameClaim, groupsClaim string
}

// Subject is "sub": the issuer's own identifier for the person, stable across
// name changes and the only one that is promised to be.
func (t *Token) Subject() string { return t.str("sub") }

// Issuer is "iss".
func (t *Token) Issuer() string { return t.str("iss") }

// Email is "email", which a provider may or may not send and may or may not
// have verified -- see [Token.EmailVerified].
func (t *Token) Email() string { return t.str("email") }

// EmailVerified is "email_verified".
//
// ⛔ An unverified email is a string the person typed. Matching people by one
// lets somebody claim to be anybody whose address they know, at any provider
// that does not check.
func (t *Token) EmailVerified() bool { return t.boolean("email_verified") }

// Username is the name to call this person, from the configured claim.
//
// The default order is preferred_username, then email, then sub. It is a
// fallback rather than a requirement because providers differ about which they
// send -- and it ends at sub, which every token has and which is the one the
// issuer promises is stable. A deployment that maps people by name should say
// which claim it means rather than take what arrives.
func (t *Token) Username() string {
	if t.usernameClaim != "" {
		return t.str(t.usernameClaim)
	}
	for _, claim := range []string{"preferred_username", "email", "sub"} {
		if v := t.str(claim); v != "" {
			return v
		}
	}
	return ""
}

// Groups is the groups claim, which providers spell differently and some do
// not send at all.
func (t *Token) Groups() []string {
	claim := t.groupsClaim
	if claim == "" {
		claim = "groups"
	}
	raw, ok := t.claims[claim]
	if !ok {
		return nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many
	}
	// Some providers send a single group as a string rather than a list of
	// one, and a server that read only lists would put that person in no
	// groups at all -- silently, which is the way access control goes wrong.
	var one string
	if err := json.Unmarshal(raw, &one); err == nil && one != "" {
		return []string{one}
	}
	return nil
}

// Audience is every "aud" in the token. It is a list in the specification and
// a string in most tokens, and both spellings mean the same thing.
func (t *Token) Audience() []string {
	raw, ok := t.claims["aud"]
	if !ok {
		return nil
	}
	var many []string
	if err := json.Unmarshal(raw, &many); err == nil {
		return many
	}
	var one string
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{one}
	}
	return nil
}

// forAudience reports whether this token is addressed to us.
func (t *Token) forAudience(want string) bool {
	for _, aud := range t.Audience() {
		if aud == want {
			return true
		}
	}
	return false
}

// Expiry is "exp".
func (t *Token) Expiry() (time.Time, bool) { return t.time("exp") }

// NotBefore is "nbf", which many tokens do not carry.
func (t *Token) NotBefore() (time.Time, bool) { return t.time("nbf") }

// IssuedAt is "iat".
func (t *Token) IssuedAt() (time.Time, bool) { return t.time("iat") }

// Claim reads any other claim into v, which is how a deployment gets at
// something this package has no opinion about.
func (t *Token) Claim(name string, v any) error {
	raw, ok := t.claims[name]
	if !ok {
		return fmt.Errorf("oidc: the token has no %q claim", name)
	}
	return json.Unmarshal(raw, v)
}

// Has reports whether a claim is present at all, which is different from
// present and empty.
func (t *Token) Has(name string) bool {
	_, ok := t.claims[name]
	return ok
}

func (t *Token) str(name string) string {
	var s string
	if raw, ok := t.claims[name]; ok {
		json.Unmarshal(raw, &s)
	}
	return s
}

func (t *Token) boolean(name string) bool {
	var b bool
	if raw, ok := t.claims[name]; ok {
		json.Unmarshal(raw, &b)
	}
	return b
}

// time reads a NumericDate (RFC 7519 §2): seconds since the epoch, possibly
// with a fraction.
func (t *Token) time(name string) (time.Time, bool) {
	raw, ok := t.claims[name]
	if !ok {
		return time.Time{}, false
	}
	var seconds float64
	if err := json.Unmarshal(raw, &seconds); err != nil {
		return time.Time{}, false
	}
	whole, frac := int64(seconds), seconds-float64(int64(seconds))
	return time.Unix(whole, int64(frac*float64(time.Second))), true
}
