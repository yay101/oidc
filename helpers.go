package oidc

import (
	"crypto/rand"
	"math/big"
)

// randString generates a cryptographically secure random string of length n.
func randString(n int) string {
	b := make([]byte, n)
	for i := range b {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letterBytes))))
		if err != nil {
			// Extremely unlikely fallback
			b[i] = letterBytes[0]
			continue
		}
		b[i] = letterBytes[num.Int64()]
	}
	return string(b)
}
