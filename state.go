package oidc

import (
	"context"
	"slices"
	"time"
)

type oidcstate struct {
	State       string
	Initiator   string
	RedirectUri string
	Provider    *Provider
	Done        context.CancelFunc
}

var states []*oidcstate

// getState retrieves an OIDC state by its state string.
func getState(state string) *oidcstate {
	// Iterate over the stored states.
	for _, s := range states {
		// If the state matches, return the state.
		if s.State == state {
			return s
		}
	}
	// If no state is found, return nil.
	return nil
}

// newState creates a new OIDC state with a timeout.
func newState(provider *Provider, uri, initiator string) *oidcstate {
	// Create a context with a 5-minute timeout
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute*5))
	// Create a new OIDC state
	new := &oidcstate{
		State:       randString(32), // Generate a random state string
		Initiator:   initiator,      // Store the initiator (e.g., user's IP address)
		Done:        cancel,         // Store the cancel function to stop the timeout
		RedirectUri: uri,            // Store the redirect URI
		Provider:    provider,       // Store the provider information
	}
	// Append the new state to the list of states
	states = append(states, new)
	// Start a goroutine to clean up the state after the timeout
	go func() {
		<-ctx.Done() // Wait for the context to be cancelled or timeout
		// Remove the state from the list of states
		for i, s := range states {
			if s == new {
				states = slices.Delete(states, i, i+1)
			}
		}
	}()
	return new
}
