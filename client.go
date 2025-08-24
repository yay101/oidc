package oidc

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"log/slog"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	// Config holds the configuration for the OIDC client
	Config ClientConfiguration
	// ProviderHandler is the HTTP handler for the provider endpoint
	ProviderHandler http.Handler
	// RedirectHandler is the HTTP handler for the redirect endpoint
	RedirectHandler http.Handler
	// Callback is a function called on successful OIDC authentication
	// It takes an IDToken and returns a success boolean and a cookie
	Callback func(IDToken) (bool, *http.Cookie)
}

type ClientConfiguration struct {
	// Domains specifies the list of domain names this OIDC client is valid for
	Domains []string
	// AuthPath is the URL path for authentication endpoint
	AuthPath string
	// LoginPath is the URL path for the login page
	LoginPath string
	// Providers contains the list of configured OIDC providers
	Providers Providers
}

type nonce struct {
	Nonce string
	Done  context.CancelFunc
}

type oidcstate struct {
	State       string
	Initiator   string
	RedirectUri string
	Provider    *Provider
	Done        context.CancelFunc
}

type idwrapper struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	State       string `json:"state"`
}

type secTime time.Time

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var (
	nonces []*nonce
	states []*oidcstate
	lj     *slog.Logger
)

// UnmarshalJSON implements the json.Unmarshaler interface for secTime.
func (s *secTime) UnmarshalJSON(data []byte) error {
	// Parse the input data as an integer representing seconds since the Unix epoch.
	secs, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		return err // Return the error if parsing fails.
	}
	// Convert the parsed seconds to a time.Time value and assign it to the secTime.
	*s = secTime(time.Unix(secs, 0))
	return nil // Return nil to indicate success.
}

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

func (p *Provider) AuthUri(r *http.Request) (string, *oidcstate) {
	// Determine the user's address, prioritizing headers
	useraddr := ""
	switch true {
	case r.Header.Get("X-Forwarded-For") != "":
		useraddr = r.Header.Get("X-Forwarded-For")
	case r.Header.Get("Forwarded-For") != "":
		useraddr = r.Header.Get("Forwarded-For")
	case r.Header.Get("X-Real-IP") != "":
		useraddr = r.Header.Get("X-Real-IP")
	default:
		useraddr = r.RemoteAddr
	}
	host, _, err := net.SplitHostPort(useraddr)
	if err != nil {
		return "", nil
	}
	// Create a new OIDC state
	state := newState(p, r.Referer(), host)
	// Construct the redirect URI
	uri, _ := url.JoinPath("https://", r.Host, p.RedirectUri)
	// Define the parameters for the authentication request
	parts := []string{}
	switch p.Type {
	case OIDC:
		parts = []string{
			"response_type=code",
			"client_id=" + p.ClientId,
			"scope=" + url.QueryEscape(strings.Join(append([]string{"openid", "email", "profile"}, p.Endpoints.Scopes...), " ")),
			"redirect_uri=" + url.QueryEscape(uri),
			"state=" + url.QueryEscape(state.State),
			"nonce=" + url.QueryEscape(newNonce().Nonce),
		}
		// Return the complete authentication URI and the OIDC state
		return p.Endpoints.AuthEndpoint + "?" + strings.Join(parts, "&"), state
	case OAuth2:
		parts = []string{
			"response_type=code",
			"client_id=" + p.ClientId,
			"scope=" + url.QueryEscape(strings.Join(p.Endpoints.Scopes, " ")),
			"response_mode=query",
			"redirect_uri=" + url.QueryEscape(uri),
			"state=" + url.QueryEscape(state.State),
		}
		// Return the complete authentication URI and the OIDC state
		return p.Endpoints.AuthEndpoint + "?" + strings.Join(parts, "&"), state
	}
	state.Done()
	return "", nil
}

func (p *Provider) codeToken(r *http.Request) (token idwrapper, err error) {
	// Construct the redirect URI
	uri, _ := url.JoinPath("https://", r.Host, p.RedirectUri)
	// Initialize an idwrapper to hold the token and state
	wrapper := idwrapper{}
	// Prepare the form values for the token request
	values := url.Values{}
	values.Add("grant_type", "authorization_code")
	values.Add("client_id", p.ClientId)
	values.Add("client_secret", p.ClientSecret)
	values.Add("redirect_uri", uri)
	values.Add("code", r.URL.Query().Get("code"))
	// Send the token request to the provider's token endpoint
	res, err := http.PostForm(p.Endpoints.TokenEndpoint, values)
	if err != nil {
		return token, err
	}
	// Check if the request was successful
	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		log.Print(res.Status, string(body))
		return token, errors.New(string(body))
	}
	// Handle different content types in the response
	switch strings.Split(res.Header.Get("Content-Type"), ";")[0] {
	case "application/json":
		// Decode the JSON response into the idwrapper
		err = json.NewDecoder(res.Body).Decode(&wrapper)
	case "application/x-www-form-urlencoded":
		// Read the response body
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return token, err
		}
		// Parse the response body as URL-encoded form data
		bv, err := url.ParseQuery(string(body))
		if err != nil {
			return token, err
		}
		// Extract the state and id_token from the parsed data
		wrapper.State = bv.Get("state")
		wrapper.IDToken = bv.Get("id_token")
	default:
		body, _ := io.ReadAll(res.Body)
		log.Print(string(body))
	}
	return wrapper, err
}
