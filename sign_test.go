package oidc_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// Tokens are signed by pyjwt, which nobody here wrote.
//
// ⛔ A token that this test file both minted and verified would prove only
// that the two halves agree with each other -- and they would, since one
// person wrote both. pyjwt is a widely used implementation of RFC 7519, and it
// signs what a provider signs.
//
// The tests that need it fail rather than skip where the environment says the
// judge is supposed to be there (OIDC_REQUIRE_JUDGE), because a skip in the
// lane that installs it looks exactly like a pass.
func sign(t *testing.T, key, alg string, claims map[string]any, headers map[string]any) string {
	t.Helper()
	python := needPyJWT(t)
	in, err := json.Marshal(map[string]any{
		"key": key, "alg": alg, "claims": claims, "headers": headers,
	})
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(python, "-c", pythonSign)
	cmd.Stdin = strings.NewReader(string(in))
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("pyjwt: %v\n%s", err, ee.Stderr)
		}
		t.Fatalf("pyjwt: %v", err)
	}
	return strings.TrimSpace(string(out))
}

const pythonSign = `
import sys, json, jwt
r = json.load(sys.stdin)
print(jwt.encode(r["claims"], r["key"], algorithm=r["alg"], headers=r["headers"] or None))
`

func needPyJWT(t *testing.T) string {
	t.Helper()
	for _, python := range []string{"python3", "python"} {
		p, err := exec.LookPath(python)
		if err != nil {
			continue
		}
		if err := exec.Command(p, "-c", "import jwt, cryptography").Run(); err == nil {
			return p
		}
	}
	if os.Getenv("OIDC_REQUIRE_JUDGE") != "" {
		t.Fatal("OIDC_REQUIRE_JUDGE is set and there is no python with pyjwt: the independent implementation " +
			"is what signs the tokens here, and this lane exists to run against it")
	}
	t.Skip("no python with pyjwt here: the tokens are signed by an independent implementation, " +
		"and the CI lane installs it")
	return ""
}
