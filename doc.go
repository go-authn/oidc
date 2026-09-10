// SPDX-License-Identifier: BSD-3-Clause

// Package oidc verifies an OpenID Connect token into an identity.
//
//	v, err := oidc.New(ctx, oidc.Config{
//	    Issuer:   "https://login.example.org",
//	    Audience: "fileshare",
//	})
//	tok, err := v.Verify(ctx, raw)   // from an Authorization: Bearer header
//	fmt.Println(tok.Subject, tok.Username, tok.Groups)
//
// A token is a signed statement by somebody else about who is asking. Almost
// all of the work is refusing the ones that are not, so the refusals are the
// package:
//
//   - ⛔ alg: none. A token that says it is unsigned is not a token; it is a
//     JSON object somebody typed.
//
//   - ⛔ An HMAC algorithm against a public key. HS256 takes a shared secret,
//     and a verifier that treats the issuer's PUBLIC key as that secret can be
//     handed a token anybody forged with it -- the key is public. Only the
//     signature algorithms the issuer actually published are accepted, and
//     HMAC is never one of them here.
//
//   - ⛔ An issuer that merely starts with the right string. "iss" is compared
//     whole: https://login.example.org.evil.test starts with the right thing.
//
//   - ⛔ A missing audience. A token minted for another service is a valid
//     token; it is simply not addressed to this one, and a server that skips
//     the check accepts every token the issuer ever signed.
//
//   - ⛔ A key fetched over cleartext HTTP, except from loopback. The JWKS is
//     what decides every signature; over a link somebody can rewrite, so is
//     everything else.
//
// # What it is not
//
// There is no login flow here: no redirect, no code exchange, no client
// secret, no cookies. This is the resource-server half -- something arrives
// with a token, and this says who that is. The half that gets people a token
// belongs to whatever is talking to them, and putting both in one package
// makes the security question twice as large for everybody who needed one of
// them.
package oidc
