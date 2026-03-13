package oidc

import (
	"context"
	"slices"
	"sync"
	"time"
)

// oidcstate stores session-specific metadata to prevent CSRF and track redirects.
type oidcstate struct {
	// State is the random string sent to the identity provider.
	State string
	// Initiator is the IP address of the user who started the authentication.
	Initiator string
	// RedirectUri is the original URL the user wanted to access after login.
	RedirectUri string
	// Provider is a reference to the OIDC provider used for this session.
	Provider *Provider
	// cancel is a function to clean up the state's internal timeout.
	cancel context.CancelFunc
}

var (
	states  []*oidcstate
	stateMu sync.RWMutex
)

// getState retrieves an OIDC state from the cache by its random string.
func getState(stateStr string) *oidcstate {
	stateMu.RLock()
	defer stateMu.RUnlock()

	for _, s := range states {
		if s.State == stateStr {
			return s
		}
	}
	return nil
}

// newState creates a new OIDC state with a 5-minute timeout.
func newState(provider *Provider, uri, initiator string) *oidcstate {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute*5))

	new := &oidcstate{
		State:       randString(32),
		Initiator:   initiator,
		cancel:      cancel,
		RedirectUri: uri,
		Provider:    provider,
	}

	stateMu.Lock()
	states = append(states, new)
	stateMu.Unlock()

	// Background cleanup routine
	go func() {
		<-ctx.Done()
		stateMu.Lock()
		defer stateMu.Unlock()
		for i, s := range states {
			if s == new {
				states = slices.Delete(states, i, i+1)
				break
			}
		}
	}()

	return new
}

// Done manually removes the state from the active cache and cancels its cleanup timer.
func (s *oidcstate) Done() {
	if s == nil {
		return
	}
	s.cancel()

	stateMu.Lock()
	defer stateMu.Unlock()
	for i, entry := range states {
		if entry == s {
			states = slices.Delete(states, i, i+1)
			break
		}
	}
}
