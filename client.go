package oidc

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"
)

// Client represents an OIDC client capable of handling multiple providers.
// It manages the orchestration of authentication requests and callbacks.
type Client struct {
	// Config holds the configuration for the OIDC client, including domains and providers.
	Config ClientConfiguration
	// ProviderHandler is the HTTP handler that initiates the OIDC flow.
	// It should be mounted at a path that includes an "id" path parameter (e.g., /auth/provider/{id}).
	ProviderHandler http.Handler
	// RedirectHandler is the HTTP handler that processes the OIDC callback from the provider.
	// It should be mounted at the RedirectUri specified in the provider configuration.
	RedirectHandler http.Handler
	// Callback is a user-defined function executed upon successful OIDC authentication.
	// It receives tokens and the verified IDToken, and returns a success status and an optional session cookie.
	Callback func(accesstoken *string, refreshtoken *string, expiry *int, idtoken IDToken) (bool, *http.Cookie)
}

// ClientConfiguration defines the global settings for the OIDC client.
type ClientConfiguration struct {
	// Domains specifies the list of allowed Host values for incoming requests.
	Domains []string
	// AuthPath is the internal URL path used for authentication redirection tracking.
	AuthPath string
	// LoginPath is the URL path where users are redirected on authentication errors.
	LoginPath string
	// Providers contains the collection of configured OIDC identity providers.
	Providers Providers
}

// idwrapper is an internal structure used to unmarshal the token response from the provider.
type idwrapper struct {
	AccessToken  *string `json:"access_token"`
	RefreshToken *string `json:"refresh_token"`
	IDToken      *string `json:"id_token"`
	ExpiresIn    *int    `json:"expires_in"`
}

// secTime is a helper type for unmarshaling Unix timestamps in seconds into time.Time.
type secTime time.Time

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var (
	lj *slog.Logger
)

// UnmarshalJSON implements the json.Unmarshaler interface for secTime.
// It converts a JSON integer (seconds since epoch) into a secTime value.
func (s *secTime) UnmarshalJSON(data []byte) error {
	secs, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		return err
	}
	*s = secTime(time.Unix(secs, 0))
	return nil
}
