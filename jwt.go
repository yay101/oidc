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
)

type IDToken struct {
	Initiator  string  `json:"ini"`
	Issuer     string  `json:"iss"`
	Subject    string  `json:"sub"`
	Audience   string  `json:"aud"`
	Email      string  `json:"email"`
	Expiration secTime `json:"exp"`
	IssuedAt   secTime `json:"iat"`
	AuthTime   secTime `json:"auth_time"`
	Nonce      string  `json:"nonce"`
}

type tokenheader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
}

type sigkey struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

type pubkey struct {
	Id  string
	Key *rsa.PublicKey
}

type sigkeywrapper struct {
	Keys []sigkey `json:"keys"`
}

func (p *Provider) getKeys() (err error) {
	// Initialize a wrapper to hold signing keys
	wrapper := sigkeywrapper{}

	// Fetch the signing keys from the provider's endpoint
	resp, err := http.Get(p.Endpoints.SigningEndpoint)
	if err != nil {
		return errors.Join(err, errors.New("failed to get signing keys from provider endpoint"))
	}

	// Decode the JSON response into our wrapper struct
	err = json.NewDecoder(resp.Body).Decode(&wrapper)
	if err != nil {
		return errors.Join(err, errors.New("failed to decode the signing keys from the response"))
	}

	// Initialize a slice to hold the public keys
	pubkeys := []pubkey{}

	// Process each key in the response
	for _, key := range wrapper.Keys {
		// Convert the JWK components (N and E) into an RSA public key
		pkey, err := generatePublicKey(key.N, key.E)
		if err != nil {
			return errors.Join(err, errors.New("failed to create pubkey from N and E values"))
		}

		// Add the key with its ID to our list of public keys
		pubkeys = append(pubkeys, pubkey{key.Kid, pkey})
	}

	// Store the public keys in the provider instance
	p.Keys = pubkeys
	return nil
}

func generatePublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	// Decode the base64 URL-encoded modulus string
	nb, err := base64.RawURLEncoding.DecodeString(nStr)
	if err != nil {
		return nil, fmt.Errorf("invalid modulus (n)")
	}

	// Convert the decoded modulus bytes to a big integer
	n := new(big.Int).SetBytes(nb)

	// Decode the base64 URL-encoded exponent string
	eb, err := base64.RawURLEncoding.DecodeString(eStr)
	if err != nil {
		return nil, fmt.Errorf("invalid exponent (e)")
	}

	// Convert the decoded exponent bytes to a big integer
	// JWT exponents are typically small values like 65537 (0x10001)
	e := new(big.Int).SetBytes(eb)

	// Construct the RSA public key from the modulus and exponent
	pubKey := &rsa.PublicKey{
		N: n,
		E: int(e.Int64()), // Convert the big integer exponent to int format required by rsa.PublicKey
	}

	// Security check: ensure the exponent is within safe bounds
	// Common exponents are 3, 17, or 65537, with 65537 being most common
	if pubKey.E < 2 || pubKey.E > 65537 {
		return nil, fmt.Errorf("invalid public key: exponent must be between 2 and 65537")
	}

	// Security check: ensure the modulus is at least 2048 bits
	// This is the minimum recommended key size for RSA in current standards
	if pubKey.N.BitLen() < 2048 {
		return nil, fmt.Errorf("invalid public key: modulus must be at least 2048 bits")
	}

	return pubKey, nil
}

func verifyRS256Signature(jwt string, pubKey *rsa.PublicKey) (bool, error) {
	// Split the JWT token into three components: header, payload, and signature
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return false, fmt.Errorf("invalid JWT format")
	}
	header := parts[0]
	payload := parts[1]
	signature := parts[2]

	// Decode the base64url-encoded signature into its binary form
	decodedSignature, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("invalid base64 signature: %w", err)
	}

	// Construct the signed message by concatenating header and payload with a period
	// This is what was originally signed by the token issuer
	message := header + "." + payload

	// Generate SHA-256 hash of the message
	// RS256 algorithm uses RSA signature with SHA-256 hashing
	hashed := sha256.Sum256([]byte(message))

	// Verify the signature using RSA PKCS#1 v1.5 signature scheme
	// The hashed[:] converts the fixed-size array to a slice as required by the VerifyPKCS1v15 function
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], decodedSignature)
	if err != nil {
		return false, fmt.Errorf("signature verification failed: %w", err)
	}

	// Signature is valid if we reach this point
	return true, nil
}
