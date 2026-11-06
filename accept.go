// SPDX-License-Identifier: BSD-3-Clause

package oidc

import (
	"fmt"
	"strings"
)

// Accepting only some institutions behind a federation proxy.
//
// A federation proxy (eduGAIN through MyAccessID, eduTEAMS, Renater, a
// Keycloak broker) authenticates people of many institutions and says which
// one in a claim. An Accept refuses the token unless that claim holds one of
// the values the service serves.
//
// The case rules come from the schemas of the claims, not from taste:
//
//   - schacHomeOrganization (claim schac_home_organization) is "domain name of
//     the home organization", a domain name conforming to RFC 1035, with
//     EQUALITY caseIgnoreMatch (SCHAC 1.6.0, schac.schema);
//   - eduPersonScopedAffiliation (eduperson_scoped_affiliation) has EQUALITY
//     caseIgnoreMatch (eduPerson schema);
//   - voperson_external_affiliation is a scoped affiliation too (AARC-G025).
//
// Those are compared without case, and only ASCII letters are folded: a
// Unicode lower-casing maps U+212A (the Kelvin sign) to "k", so "univ-K.fr"
// would match "univ-k.fr". Every other claim is compared exactly.

var foldedClaims = map[string]bool{
	"schac_home_organization":       true,
	"schachomeorganization":         true,
	"eduperson_scoped_affiliation":  true,
	"edupersonscopedaffiliation":    true,
	"voperson_external_affiliation": true,
}

// FoldsCase says whether values of claim are compared without case.
func FoldsCase(claim string) bool { return foldedClaims[ASCIILower(claim)] }

// Normalize is the form values of claim are compared in: ASCII-lower-cased
// (and without one trailing dot) for the claims that fold, as they are
// otherwise.
func Normalize(claim, v string) string {
	if !FoldsCase(claim) {
		return v
	}
	return ASCIILower(strings.TrimSuffix(v, "."))
}

// ASCIILower folds A-Z only: the fold the schema's caseIgnoreMatch is read as
// for the names this package returns, and the one every consumer of those names
// must use. strings.ToLower and strings.EqualFold fold Unicode, which equates
// the Kelvin sign U+212A with "k": "Kate" and "kate" are two accounts at an
// issuer, and one to a consumer that folds Unicode.
func ASCIILower(s string) string {
	for i := 0; i < len(s); i++ {
		if c := s[i]; 'A' <= c && c <= 'Z' {
			b := []byte(s)
			for j := i; j < len(b); j++ {
				if 'A' <= b[j] && b[j] <= 'Z' {
					b[j] += 'a' - 'A'
				}
			}
			return string(b)
		}
	}
	return s
}

// EqualASCIIFold reports whether a and b are the same name under [ASCIILower].
func EqualASCIIFold(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		x, y := a[i], b[i]
		if 'A' <= x && x <= 'Z' {
			x += 'a' - 'A'
		}
		if 'A' <= y && y <= 'Z' {
			y += 'a' - 'A'
		}
		if x != y {
			return false
		}
	}
	return true
}

// ClaimValues reads a claim as strings: a string, or a list of strings. A
// claim that is absent, or has any other shape (a number, an object, a list
// with a non-string in it), has no values. The names "" and "groups" are the
// token's groups claim ([Token.Groups]).
func ClaimValues(t *Token, name string) []string {
	if name == "" || name == "groups" {
		return t.Groups()
	}
	var one string
	if err := t.Claim(name, &one); err == nil {
		return []string{one}
	}
	var many []string
	if err := t.Claim(name, &many); err == nil {
		return many
	}
	return nil
}

// An Accept is "Claim holds one of Values". Several Accepts all have to hold.
type Accept struct {
	Claim  string
	Values []string
}

// HoldsValues reports whether one of got is one of a.Values.
func (a Accept) HoldsValues(got []string) bool {
	for _, v := range got {
		nv := Normalize(a.Claim, v)
		for _, w := range a.Values {
			if nv == Normalize(a.Claim, w) {
				return true
			}
		}
	}
	return false
}

// Holds reports whether the token's claim holds one of a.Values. An empty
// Values accepts nobody.
func (a Accept) Holds(t *Token) bool { return a.HoldsValues(ClaimValues(t, a.Claim)) }

// A Refusal says which Accept a token failed.
type Refusal struct {
	Claim string
	// Value is the first value the token stated, cleaned to printable ASCII
	// and bounded, so it can be shown back; "" when the token stated none.
	Value string
}

func (r *Refusal) Error() string {
	if r.Value == "" {
		return fmt.Sprintf("oidc: the token does not state %q", r.Claim)
	}
	return fmt.Sprintf("oidc: %q = %q is not among the accepted values", r.Claim, r.Value)
}

// Check applies every Accept to the token and returns the first it fails, or
// nil.
func Check(accepts []Accept, t *Token) *Refusal {
	for _, a := range accepts {
		vals := ClaimValues(t, a.Claim)
		if !a.HoldsValues(vals) {
			return &Refusal{Claim: a.Claim, Value: shown(vals)}
		}
	}
	return nil
}

func shown(vals []string) string {
	if len(vals) == 0 {
		return ""
	}
	var b strings.Builder
	for _, r := range vals[0] {
		if r >= 0x20 && r < 0x7f && b.Len() < 64 {
			b.WriteRune(r)
		}
	}
	return b.String()
}
