package oidc_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/go-authn/oidc"
)

func TestScopedName(t *testing.T) {
	allowed := []string{"univ-a.fr", "Univ-B.FR."}
	for _, tc := range []struct {
		name, def string
		want      string
		err       error
	}{
		{"alice@univ-a.fr", "", "alice@univ-a.fr", nil},
		{"Alice@UNIV-A.FR", "", "alice@univ-a.fr", nil},
		{"alice@univ-b.fr.", "", "alice@univ-b.fr", nil},
		{"alice@univ-z.fr", "", "", oidc.ErrScopeNotAllowed},
		{"alice@evil-univ-a.fr", "", "", oidc.ErrScopeNotAllowed},
		{"alice@sub.univ-a.fr", "", "", oidc.ErrScopeNotAllowed},
		{"alice@univ-K.fr", "", "", oidc.ErrScopeNotAllowed}, // Kelvin sign is not k
		{"alice", "", "", oidc.ErrNoScope},
		{"alice", "univ-a.fr", "alice@univ-a.fr", nil},
		{"alice", "univ-z.fr", "", oidc.ErrScopeNotAllowed}, // the default scope must be allowed too
		{"a@b@univ-a.fr", "", "", oidc.ErrBadName},          // exactly one @
		{"alice@univ-a.fr@univ-z.fr", "", "", oidc.ErrBadName},
		{"@univ-a.fr", "", "", oidc.ErrBadName},
		{"alice@", "", "", oidc.ErrBadName},
		{"al ice@univ-a.fr", "", "", oidc.ErrBadName},
		{"alice\n@univ-a.fr", "", "", oidc.ErrBadName},
		{"", "", "", oidc.ErrNoScope},
		{strings.Repeat("a", 200) + "@univ-a.fr", "", "", oidc.ErrBadName},
	} {
		got, err := oidc.ScopedName(tc.name, allowed, tc.def)
		if got != tc.want || !errors.Is(err, tc.err) && err != tc.err {
			t.Errorf("%q (default %q): %q, %v; want %q, %v", tc.name, tc.def, got, err, tc.want, tc.err)
		}
	}
	if _, err := oidc.ScopedName("alice@univ-a.fr", nil, ""); !errors.Is(err, oidc.ErrScopeNotAllowed) {
		t.Errorf("no allowed scope: %v", err)
	}
}

func FuzzScopedName(f *testing.F) {
	f.Add("alice@univ-a.fr", "univ-a.fr", "")
	f.Add("alice", "univ-a.fr", "univ-a.fr")
	f.Fuzz(func(t *testing.T, name, allowed, def string) {
		got, err := oidc.ScopedName(name, []string{allowed}, def)
		if err != nil {
			if got != "" {
				t.Fatalf("a name with an error: %q", got)
			}
			return
		}
		// What comes back is local@scope, scope allowed, stable, no controls.
		i := strings.LastIndexByte(got, '@')
		if i <= 0 || i == len(got)-1 {
			t.Fatalf("not local@scope: %q", got)
		}
		if again, err := oidc.ScopedName(got, []string{allowed}, ""); err != nil || again != got {
			t.Fatalf("not stable: %q -> %q, %v", got, again, err)
		}
		if strings.ContainsAny(got, " \t\r\n\x00") {
			t.Fatalf("control or space in %q", got)
		}
	})
}
