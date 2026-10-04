# oidc

[![Go Reference](https://pkg.go.dev/badge/github.com/go-authn/oidc.svg)](https://pkg.go.dev/github.com/go-authn/oidc)
[![License](https://img.shields.io/badge/license-BSD--3--Clause-0A6E96?style=flat-square)](LICENSE)
[![CI](https://github.com/go-authn/oidc/actions/workflows/ci.yml/badge.svg)](https://github.com/go-authn/oidc/actions/workflows/ci.yml)

**Verify an OpenID Connect token into an identity.** Discovery, JWKS, and the
refusals that matter. Pure Go, `CGO_ENABLED=0`, **no dependencies**.

```go
v, err := oidc.New(ctx, oidc.Config{
    Issuer:   "https://login.example.org",
    Audience: "fileshare",
})

tok, err := v.Verify(ctx, raw)          // from an Authorization: Bearer header
fmt.Println(tok.Subject(), tok.Username(), tok.Groups())
```

A token is a signed statement by somebody else about who is asking. Almost all
of the work is refusing the ones that are not, so the refusals **are** the
package.

## What it accepts

Ten signature algorithms, as an **allowlist** — a token whose `alg` is not one
of these is refused before any key is fetched:

| family | algorithms |
|---|---|
| RSASSA-PKCS1-v1_5 | `RS256` `RS384` `RS512` |
| RSASSA-PSS | `PS256` `PS384` `PS512` |
| ECDSA | `ES256` `ES384` `ES512` |
| EdDSA (Ed25519) | `EdDSA` |

An allowlist rather than a list of things to reject, because the two fail
differently: a denylist is only as complete as the taxonomy it was written
from, and the algorithm it has never heard of is the one it lets through.
`alg: none` and the HMAC family are refused by *not being here*, which is a
stronger statement than a rule naming them — and the table below says why each
would be wrong.

## What it refuses

| | why |
|---|---|
| `alg: none` | a token that says it is unsigned is not a token; it is a JSON object somebody typed |
| **HMAC** against a public key | `HS256` takes a shared *secret*, and a verifier that uses the issuer's **public** key as that secret accepts a token anybody can mint. The oldest JWT attack there is |
| an issuer that merely **starts with** the right one | `https://login.example.org.evil.test` starts with the right string |
| a missing or wrong **audience** | a token minted for another service is a valid token; it is simply not addressed to this one |
| a token with **no expiry** | that is not a token, it is a password somebody can copy once |
| an **issuer** or a **key set over cleartext HTTP** | the JWKS decides every signature, and discovery at the issuer says where the JWKS is; over a link somebody can rewrite, so does everything else. Refused by `New`. Loopback is exempt — there is no link |
| an RSA key **under 2048 bits**, an EC point **not on the curve** | a short key is not a small inconvenience: it is a signature somebody else can produce |
| a key published for **encryption** (`use: enc`) | a key set legitimately holds both, and only one of them checks signatures |

Everything wrong with a token is **one error to the caller** — a client that
sent a token it should not have is not owed an explanation of which check
caught it — while the detail goes to the server's own log.

## Keys rotate, and an unknown key is not a way to hammer the issuer

A signature that nothing held can verify is worth **one** refetch per
`MinRefresh` (a minute by default). That covers both a new `kid` and — the
inadvisable thing several providers do — the **same `kid` with a new key**. A
verifier that only refetched on an unknown `kid` would refuse every token from
the moment of the roll until it was restarted.

The bound is on **attempts**, not successes, and it holds for requests that
arrive together:

- tokens that need the key set while a fetch is under way **wait for that
  fetch** instead of starting their own — two hundred at once are one request
  to the issuer;
- a fetch that **fails** still counts. While the issuer's key set is down, it
  is asked once per `MinRefresh`, not once per forged token.

Before v0.2.0 neither held: concurrent tokens each fetched, and a failing key
set was asked again for every token.

## Which name `Username()` gives

By default `preferred_username`, then `email` **only when `email_verified` is
`true`**, then `sub`. An email the issuer did not verify is a string the person
typed (OIDC Core §5.1); taking it as a name would admit a correctly signed
token under somebody else's address. `sub` with `iss` is the only identifier
the issuer promises is stable (OIDC Core §5.7), and the fallback ends there.

A configured `UsernameClaim` is read as named, with no fallback and no
`email_verified` check.

**Changed in v0.2.0**: earlier versions fell back to `email` whether or not it
was verified. A deployment that relied on that, with an issuer that does not
send `email_verified`, now gets `sub` instead — and should name the claim it
means.

## What it is not

There is no login flow here: no redirect, no code exchange, no client secret,
no cookies. This is the **resource-server** half — something arrives with a
token, and this says who that is. The half that gets people a token belongs to
whatever is talking to them, and putting both in one package makes the security
question twice as large for everybody who needed one of them.

## Verified against tokens this repository did not sign

- **pyjwt** signs every token in the test suite. A token this repository both
  minted and verified would prove only that its two halves agree with each
  other — and one person wrote both.
- The **HMAC-confusion** token is forged by hand in the test, because pyjwt
  *refuses to produce it*: "the specified key is an asymmetric key … and should
  not be used as an HMAC secret". An independent implementation agreeing that
  the shape is an attack rather than a use is worth writing down.
- **Committed vectors** — `testdata/fixed.json`, signed once by pyjwt with a
  fixed key — mean the architecture lanes verify real signatures too, including
  **s390x**, where a byte-order mistake in the JWKS arithmetic would show. The
  clock is fixed there, because a committed token expires.
- The three refusals that would be catastrophic if they quietly stopped working
  were **sabotage-checked**: accepting HMAC, comparing the issuer by prefix, and
  skipping the audience check each make a test say *the token was ACCEPTED*.

## Licence

BSD-3-Clause.
