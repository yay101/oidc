package oidc

import (
	"context"
	"slices"
	"sync"
	"time"
)

// nonce represents a security token used once to prevent replay attacks.
type nonce struct {
	// Nonce is the random string value.
	Nonce string
	// Done is a cancel function to manually invalidate the nonce or clean up resources.
	Done context.CancelFunc
}

var (
	nonces  []*nonce
	nonceMu sync.Mutex
)

// getNonce searches for a nonce in the active cache.
// If found, it invalidates the nonce (ensuring single use) and returns true.
func getNonce(nonceStr string) bool {
	nonceMu.Lock()
	defer nonceMu.Unlock()

	for i, n := range nonces {
		if n.Nonce == nonceStr {
			n.Done() // Trigger cleanup
			nonces = slices.Delete(nonces, i, i+1)
			return true
		}
	}
	return false
}

// newNonce generates a new random nonce with a 5-minute validity window.
// It automatically handles its own cleanup after the timeout.
func newNonce() *nonce {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute*5))

	new := &nonce{
		Nonce: randString(32),
		Done:  cancel,
	}

	nonceMu.Lock()
	nonces = append(nonces, new)
	nonceMu.Unlock()

	// Self-cleanup routine
	go func() {
		<-ctx.Done()
		nonceMu.Lock()
		defer nonceMu.Unlock()
		for i, n := range nonces {
			if n == new {
				nonces = slices.Delete(nonces, i, i+1)
				break
			}
		}
	}()

	return new
}
