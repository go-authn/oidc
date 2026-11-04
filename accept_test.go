package oidc_test

import (
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/go-authn/oidc"
)

func countHandler(h http.Handler, n *atomic.Int64) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { n.Add(1); h.ServeHTTP(w, r) })
}

func TestAcceptHoldsValues(t *testing.T) {
	for _, tc := range []struct {
		claim  string
		accept []string
		got    []string
		want   bool
	}{
		{"schac_home_organization", []string{"univ-a.fr"}, []string{"UNIV-A.FR"}, true},
		{"schac_home_organization", []string{"univ-a.fr"}, []string{"univ-a.fr."}, true},
		{"schac_home_organization", []string{"univ-a.fr"}, []string{"x.univ-a.fr"}, false},
		{"schac_home_organization", []string{"univ-a.fr"}, nil, false},
		{"schacHomeOrganization", []string{"Univ-A.fr"}, []string{"univ-a.FR"}, true},
		{"eduperson_scoped_affiliation", []string{"member@univ-a.fr"}, []string{"faculty@x", "Member@Univ-A.fr"}, true},
		{"voperson_external_affiliation", []string{"member@univ-a.fr"}, []string{"MEMBER@UNIV-A.FR"}, true},
		{"groups", []string{"Admins"}, []string{"admins"}, false}, // exact
		{"groups", []string{"admins"}, []string{"x", "admins"}, true},
		{"schac_home_organization", nil, []string{"univ-a.fr"}, false}, // no values accepts nobody
		// The Kelvin sign is not "k": only ASCII is folded.
		{"schac_home_organization", []string{"univ-k.fr"}, []string{"univ-K.fr"}, false},
		{"schac_home_organization", []string{"univ-K.fr"}, []string{"univ-k.fr"}, false},
		{"schac_home_organization", []string{"univ-k.fr"}, []string{"UNIV-K.FR"}, true},
	} {
		if got := (oidc.Accept{Claim: tc.claim, Values: tc.accept}).HoldsValues(tc.got); got != tc.want {
			t.Errorf("%s %v in %v: %v", tc.claim, tc.accept, tc.got, got)
		}
	}
}

func FuzzAccept(f *testing.F) {
	f.Add("schac_home_organization", "univ-a.fr", "UNIV-A.fr.")
	f.Add("groups", "a", "a")
	f.Fuzz(func(t *testing.T, claim, accepted, got string) {
		if !(oidc.Accept{Claim: claim, Values: []string{got}}).HoldsValues([]string{got}) {
			t.Fatal("a value does not match itself")
		}
		if oidc.Normalize(claim, accepted) != oidc.Normalize(claim, got) && (oidc.Accept{Claim: claim, Values: []string{accepted}}).HoldsValues([]string{got}) {
			t.Fatal("different values match")
		}
	})
}
