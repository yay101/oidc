package oidc

import (
	"context"
	"slices"
	"time"
)

type nonce struct {
	Nonce string
	Done  context.CancelFunc
}

var nonces []*nonce

// getNonce checks if a nonce exists and cancels its context if found.
func getNonce(nonce string) bool {
	// Iterate over the list of nonces.
	for _, n := range nonces {
		// Check if the nonce matches.
		if n.Nonce == nonce {
			// Cancel the context associated with the nonce.
			n.Done()
			// Return true to indicate that the nonce was found.
			return true
		}
	}
	// Return false if the nonce was not found.
	return false
}

// newNonce creates a new nonce with a timeout.
func newNonce() *nonce {
	// Create a context with a 5-minute timeout
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute*5))
	// Create a new nonce
	new := &nonce{
		Nonce: randString(32), // Generate a random nonce string
		Done:  cancel,         // Store the cancel function to stop the timeout
	}
	// Append the new nonce to the list of nonces
	nonces = append(nonces, new)
	// Start a goroutine to clean up the nonce after the timeout
	go func() {
		<-ctx.Done() // Wait for the context to be cancelled or timeout
		// Remove the nonce from the list of nonces
		for i, n := range nonces {
			if n == new {
				nonces = slices.Delete(nonces, i, i+1)
			}
		}
	}()
	return new
}
