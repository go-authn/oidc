# Changelog

## v0.8.1

- The https-or-loopback rule and the redirect policy now come from
  `github.com/go-authn/harden/redirect` (closes #26), shared with rp, awscred,
  saml and wireguard. Stricter than before: an `https:///x` URL with no host is
  refused; `LOCALHOST` and `localhost.` are loopback; an IPv6 zone is not; the
  error names the scheme and host, no longer the whole URL (it may carry a
  secret). `.localhost` with an empty label is no longer loopback.

## v0.8.0

Security audit 2026-11-21.

- ES256, ES384 and ES512 verify only with a key on P-256, P-384 and P-521
  respectively (RFC 7518 §3.4). Before, ES256 verified with a P-384 or P-521
  key if the signature had that curve's length. Breaking for a deployment
  whose issuer signs with a key on the wrong curve for its `alg`.
- A JWK's `alg` is honoured (RFC 7517 §4.4): a key published for RS256 no
  longer verifies an RS512 or PS256 token. A key with no `alg` is unchanged.
  Breaking for an issuer that publishes a wrong `alg`.
- `PeekIssuer` reads the claim `iss` exactly. `encoding/json` folds case, so a
  payload `{"ISS": ...}` used to route the token to another issuer's verifier
  (still refused there, but routed).
