package oidc

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"sync"
)

// IDToken represents the standard claims in an OpenID Connect ID Token.
type IDToken struct {
	// Initiator is the recorded IP address of the user who started the auth flow.
	Initiator string `json:"ini"`
	// Issuer is the URL of the identity provider.
	Issuer string `json:"iss"`
	// Subject is the unique identifier for the user within the provider.
	Subject string `json:"sub"`
	// Audience is the Client ID the token was issued for.
	Audience string `json:"aud"`
	// Email is the user's email address, if requested in scopes.
	Email string `json:"email"`
	// Expiration is when the token becomes invalid.
	Expiration secTime `json:"exp"`
	// IssuedAt is when the token was created.
	IssuedAt secTime `json:"iat"`
	// AuthTime is when the user actually authenticated.
	AuthTime secTime `json:"auth_time"`
	// Nonce is the random string used to prevent replay attacks.
	Nonce string `json:"nonce"`
}

// tokenheader represents the JWT header segment.
type tokenheader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

// sigkey represents a JSON Web Key (JWK).
type sigkey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"` // Modulus
	E   string `json:"e"` // Exponent
}

// pubkey is an internal cache for parsed RSA public keys.
type pubkey struct {
	Id  string
	Key *rsa.PublicKey
}

// sigkeywrapper is used to unmarshal the JWKS response.
type sigkeywrapper struct {
	Keys []sigkey `json:"keys"`
}

var (
	keyCache   = make(map[string][]pubkey)
	keyCacheMu sync.RWMutex
)

// getKeys fetches and parses the identity provider's public keys from their JWKS endpoint.
func (p *Provider) getKeys() (err error) {
	wrapper := sigkeywrapper{}

	resp, err := http.Get(p.Endpoints.SigningEndpoint)
	if err != nil {
		return errors.Join(err, errors.New("failed to reach JWKS endpoint"))
	}
	defer resp.Body.Close()

	err = json.NewDecoder(resp.Body).Decode(&wrapper)
	if err != nil {
		return errors.Join(err, errors.New("failed to decode JWKS response"))
	}

	pubkeys := []pubkey{}
	for _, key := range wrapper.Keys {
		pkey, err := generatePublicKey(key.N, key.E)
		if err != nil {
			continue // Skip invalid keys
		}
		pubkeys = append(pubkeys, pubkey{key.Kid, pkey})
	}

	keyCacheMu.Lock()
	keyCache[p.Id] = pubkeys
	keyCacheMu.Unlock()

	return nil
}

// GetCachedKeys safely retrieves the provider's public keys.
func (p *Provider) GetCachedKeys() []pubkey {
	keyCacheMu.RLock()
	defer keyCacheMu.RUnlock()
	return keyCache[p.Id]
}

// generatePublicKey converts raw modulus and exponent strings from a JWK into an RSA public key.
func generatePublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	nb, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("invalid modulus (n)")
	}
	n := new(big.Int).SetBytes(nb)

	eb, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("invalid exponent (e)")
	}
	e := new(big.Int).SetBytes(eb)

	pubKey := &rsa.PublicKey{
		N: n,
		E: int(e.Int64()),
	}

	// Basic security checks
	if pubKey.E < 2 || pubKey.E > 65537 {
		return nil, fmt.Errorf("invalid public key: exponent out of range")
	}
	if pubKey.N.BitLen() < 2048 {
		return nil, fmt.Errorf("invalid public key: modulus too small")
	}

	return pubKey, nil
}

// verifyRS256Signature verifies a JWT signature using the provided RSA public key.
func verifyRS256Signature(jwt string, pubKey *rsa.PublicKey) (bool, error) {
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return false, fmt.Errorf("invalid JWT structure")
	}

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return false, fmt.Errorf("invalid signature encoding: %w", err)
	}

	message := parts[0] + "." + parts[1]
	hashed := sha256.Sum256([]byte(message))

	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		return false, fmt.Errorf("signature verification failed: %w", err)
	}

	return true, nil
}
