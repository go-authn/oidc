// SPDX-License-Identifier: BSD-3-Clause

package oidc_test

import (
	"testing"

	"github.com/go-authn/oidc"
)

func TestASCIIFoldDoesNotEquateTheKelvinSign(t *testing.T) {
	const kate = "Kate" // KELVIN SIGN: a different account at the issuer
	for _, tc := range []struct {
		a, b string
		want bool
	}{
		{"Kate", "kate", true},
		{"KATE@UNIV-A.FR", "kate@univ-a.fr", true},
		{kate, "kate", false},
		{kate, "Kate", false},
		{"kate", "kat", false},
		{"", "", true},
	} {
		if got := oidc.EqualASCIIFold(tc.a, tc.b); got != tc.want {
			t.Errorf("EqualASCIIFold(%q, %q) = %v, want %v", tc.a, tc.b, got, tc.want)
		}
	}
	if got := oidc.ASCIILower(kate); got != kate {
		t.Errorf("ASCIILower folded the Kelvin sign: %q", got)
	}
	if got := oidc.ASCIILower("Kate"); got != "kate" {
		t.Errorf("ASCIILower(Kate) = %q", got)
	}
}
