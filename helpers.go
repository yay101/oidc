package oidc

import "math/rand"

// randString generates a random string of length n using the characters in letterBytes.
func randString(n int) string {
	// Create a byte slice of length n.
	b := make([]byte, n)
	// Iterate over the byte slice and fill it with random characters from letterBytes.
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	// Convert the byte slice to a string and return it.
	return string(b)
}
