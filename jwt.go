package oidc

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"strings"
	"time"
)

type IDToken struct {
	Issuer     string    `json:"iss"`
	Subject    string    `json:"sub"`
	Audience   string    `json:"aud"`
	Expiration time.Time `json:"exp"`
	IssuedAt   time.Time `json:"iat"`
	AuthTime   time.Time `json:"auth_time"`
	Nonce      string    `json:"nonce"`
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

var (
	pubkeys []pubkey
)

func (p *Provider) getKeys() []pubkey {
	wrapper := sigkeywrapper{}
	resp, err := http.Get(p.SigningKeyLink)
	if err != nil {
		log.Print(err)
	}
	json.NewDecoder(resp.Body).Decode(&wrapper)
	for _, key := range wrapper.Keys {
		pkey, err := generatePublicKey(key.N, key.E)
		if err != nil {
			log.Print(err)
		}
		pubkeys = append(pubkeys, pubkey{key.Kid, pkey})
	}
	return pubkeys
}

func generatePublicKey(nStr, eStr string) (*rsa.PublicKey, error) {
	// 1. Convert n and e from strings to big.Int
	n, ok := new(big.Int).SetString(nStr, 10)
	if !ok {
		return nil, fmt.Errorf("invalid modulus (n)")
	}

	e, ok := new(big.Int).SetString(eStr, 10) // e might be small, but big.Int is more general
	if !ok {
		return nil, fmt.Errorf("invalid exponent (e)")
	}

	// 2. Create the RSA public key
	pubKey := &rsa.PublicKey{
		N: n,
		E: int(e.Int64()), // Convert e to int.  JWT e is usually small.
	}

	// Important: check if the public key is valid.
	if pubKey.E < 2 || pubKey.E > 65537 {
		return nil, fmt.Errorf("invalid public key: exponent must be between 2 and 65537")
	}

	if pubKey.N.BitLen() < 2048 {
		return nil, fmt.Errorf("invalid public key: modulus must be at least 2048 bits")
	}

	return pubKey, nil
}

func verifyRS256Signature(jwt string, pubKey *rsa.PublicKey) (bool, error) {
	// 1. Split the JWT into its parts (header.payload.signature)
	parts := strings.Split(jwt, ".")
	if len(parts) != 3 {
		return false, fmt.Errorf("invalid JWT format")
	}
	header := parts[0]
	payload := parts[1]
	signature := parts[2]

	// 2. Decode the signature from base64
	decodedSignature, err := base64.RawURLEncoding.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("invalid base64 signature: %w", err)
	}

	// 3. Create the message to be verified (header.payload)
	message := header + "." + payload

	// 4. Hash the message using SHA256 (as RS256 uses SHA256)
	hashed := sha256.Sum256([]byte(message))

	// 5. Verify the signature
	err = rsa.VerifyPKCS1v15(pubKey, crypto.SHA256, hashed[:], decodedSignature) // Note the [:] to get a slice
	if err != nil {
		return false, fmt.Errorf("signature verification failed: %w", err)
	}

	return true, nil
}
