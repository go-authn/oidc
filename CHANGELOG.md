# Changelog

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
