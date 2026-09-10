// SPDX-License-Identifier: BSD-3-Clause

package oidc

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"hash"
	"math/big"
	"strings"
)

// A jose header is the first part of a token: what signed it, and with which
// key.
type joseHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// split takes a compact serialisation apart without verifying anything.
//
// The signing input is the first two parts JOINED BY A DOT, exactly as they
// arrived -- not re-encoded from the decoded values. Two encodings of the same
// JSON have different signatures, and re-encoding is how a verifier ends up
// checking a signature over bytes the issuer never signed.
func split(raw string) (header joseHeader, payload, signed, signature []byte, err error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return header, nil, nil, nil, fmt.Errorf("oidc: a token has three parts and this has %d", len(parts))
	}
	rawHeader, err := decode(parts[0])
	if err != nil {
		return header, nil, nil, nil, fmt.Errorf("oidc: the header: %w", err)
	}
	if err := json.Unmarshal(rawHeader, &header); err != nil {
		return header, nil, nil, nil, fmt.Errorf("oidc: the header is not JSON: %w", err)
	}
	if payload, err = decode(parts[1]); err != nil {
		return header, nil, nil, nil, fmt.Errorf("oidc: the payload: %w", err)
	}
	if signature, err = decode(parts[2]); err != nil {
		return header, nil, nil, nil, fmt.Errorf("oidc: the signature: %w", err)
	}
	return header, payload, []byte(parts[0] + "." + parts[1]), signature, nil
}

// decode is base64url without padding, which is what JOSE uses (RFC 7515 §2).
func decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

// verifySignature checks one signature with one key.
//
// ⛔ The algorithm comes from the KEY as much as from the header: a token
// claiming RS256 is checked with an RSA key or refused, never with whatever
// key happens to have the right kid. That is the other half of refusing HMAC
// -- an attacker who can choose the algorithm chooses what the key means.
func verifySignature(alg string, key any, signed, signature []byte) error {
	h, err := hashFor(alg)
	if err != nil {
		return err
	}
	var digest []byte
	if h != 0 {
		hasher := h.New()
		hasher.Write(signed)
		digest = hasher.Sum(nil)
	}
	switch {
	case strings.HasPrefix(alg, "RS"), strings.HasPrefix(alg, "PS"):
		pub, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("oidc: the token says %s and the key is %T", alg, key)
		}
		if strings.HasPrefix(alg, "PS") {
			return rsa.VerifyPSS(pub, h, digest, signature, &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthEqualsHash})
		}
		return rsa.VerifyPKCS1v15(pub, h, digest, signature)
	case strings.HasPrefix(alg, "ES"):
		pub, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("oidc: the token says %s and the key is %T", alg, key)
		}
		// JOSE writes an ECDSA signature as r||s, each padded to the curve's
		// byte length (RFC 7518 §3.4) -- not the ASN.1 sequence
		// ecdsa.VerifyASN1 takes.
		n := (pub.Curve.Params().BitSize + 7) / 8
		if len(signature) != 2*n {
			return fmt.Errorf("oidc: an %s signature is %d bytes and this is %d", alg, 2*n, len(signature))
		}
		r := new(big.Int).SetBytes(signature[:n])
		s := new(big.Int).SetBytes(signature[n:])
		if !ecdsa.Verify(pub, digest, r, s) {
			return errBadSignature
		}
		return nil
	case alg == "EdDSA":
		pub, ok := key.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("oidc: the token says EdDSA and the key is %T", key)
		}
		if !ed25519.Verify(pub, signed, signature) {
			return errBadSignature
		}
		return nil
	}
	return fmt.Errorf("oidc: nothing here verifies %q", alg)
}

// hashFor is the digest an algorithm signs over. EdDSA signs the message
// itself, and answers 0.
func hashFor(alg string) (crypto.Hash, error) {
	switch alg {
	case "RS256", "PS256", "ES256":
		return crypto.SHA256, nil
	case "RS384", "PS384", "ES384":
		return crypto.SHA384, nil
	case "RS512", "PS512", "ES512":
		return crypto.SHA512, nil
	case "EdDSA":
		return 0, nil
	}
	return 0, fmt.Errorf("oidc: nothing here verifies %q", alg)
}

// signatureAlgorithms are the ones this package will ever accept.
//
// ⛔ HMAC (HS256 and friends) is deliberately absent and is not an oversight.
// It takes a SHARED secret, and a verifier that reaches for the issuer's
// public key to check one accepts a token anybody can mint: the key is
// public. An issuer that signs ID tokens with HS256 shares a secret with each
// client, which is a different design from this one, and mixing the two is
// the oldest JWT vulnerability there is.
var signatureAlgorithms = map[string]bool{
	"RS256": true, "RS384": true, "RS512": true,
	"PS256": true, "PS384": true, "PS512": true,
	"ES256": true, "ES384": true, "ES512": true,
	"EdDSA": true,
}

var _ hash.Hash // for the crypto/sha imports, which register the hashes

func init() {
	// The hashes must be linked in for crypto.Hash.New to work; importing
	// them for their side effect is how that is done, and naming them here
	// keeps a tidy-up from removing the imports.
	_ = sha256.New
	_ = sha512.New
}
