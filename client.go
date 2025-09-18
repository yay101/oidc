package oidc

import (
	"log/slog"
	"net/http"
	"strconv"
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

type idwrapper struct {
	AccessToken string `json:"access_token"`
	IDToken     string `json:"id_token"`
	State       string `json:"state"`
	Code        string `json:"code"`
}

type secTime time.Time

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var (
	lj *slog.Logger
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
