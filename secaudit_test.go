package oidc_test

import (
	"strings"
	"testing"

	"github.com/go-authn/oidc"
)

// Security audit 2026-11-05 (untracked proof). ScopedName accepts a name with
// several "@" and returns it unchanged, so the identity it vouches for as
// "local@univ-a.fr" reads, to any consumer that splits at the FIRST "@"
// (strings.Cut, net/mail, SQL SPLIT_PART, sshd's %u@%h logs), as being in
// scope evil.example. go-authn/saml refuses the same shape for this reason
// (metadata.go inScope: strings.Count(value, "@") != 1).
func TestSecAuditScopedNameTwoAts(t *testing.T) {
	got, err := oidc.ScopedName("admin@evil.example@univ-a.fr", []string{"univ-a.fr"}, "")
	if err != nil {
		return // refused: what saml does
	}
	_, firstScope, _ := strings.Cut(got, "@")
	t.Errorf("accepted as %q; a first-@ reader sees scope %q, which univ-a.fr's issuer may not assert", got, firstScope)
}
