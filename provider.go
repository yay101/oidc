package oidc

import (
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
)

type Providers []Provider

type providertype string

const (
	Unset  providertype = ""
	OIDC   providertype = "oidc"
	OAuth2 providertype = "oauth2"
)

// Provider defines the configuration and runtime state for an OpenID Connect (OIDC) identity provider.
type Provider struct {
	// Unique identifier for the provider.
	Id string `json:"id"`
	// Whether the provider is enabled for use.
	Enabled bool `json:"enabled"`
	// Switch between OIDC and OAuth2
	Type providertype `json:"type"`
	// Display name for the provider.
	Name string `json:"name"`
	// URL or base64 encoded string of the provider's logo.
	Logo string `json:"logo"`
	// The client ID issued to the application by the provider.
	ClientId string `json:"clientid"`
	// The client secret issued to the application by the provider.
	ClientSecret string `json:"clientsecret"`
	// The discovery endpoint URL for the provider's OIDC configuration.
	ConfigurationLink string `json:"configurationlink"`
	// The redirect URI registered with the provider.
	RedirectUri string `json:"redirecturi"`
	// Any error encountered during provider setup or discovery.
	Error error `json:"errors"`
	// Discovered OIDC endpoint configuration from the provider.
	Endpoints EndpointConfiguration `json:"-"`
	// List of valid issuer URLs for this provider.
	Issuers []string `json:"issuers"`
	// Public keys for verifying ID token signatures.
	Keys []pubkey `json:"-"`
}

type EndpointConfiguration struct {
	// AuthEndpoint is the URL of the authorization endpoint.
	AuthEndpoint string `json:"authorization_endpoint"`
	// TokenEndpoint is the URL of the token endpoint.
	TokenEndpoint string `json:"token_endpoint"`
	// SigningEndpoint is the URL of the JWKS (JSON Web Key Set) endpoint, which provides public keys for verifying signatures.
	SigningEndpoint string `json:"jwks_uri"`
	// Algorithm is a list of JWS signing algorithms supported by the OP for the ID Token.
	Algorithm []string `json:"id_token_signing_alg_values_supported"`
	// ClaimsSupported is a list of the claims that the OP supports.
	ClaimsSupported []string `json:"claims_supported"`
	// GrantTypes is a list of the OAuth 2.0 Grant Type values that this OP supports.
	GrantTypes []string `json:"grant_types_supported"`
	// Scopes is a list of the scopes that the OP supports.
	Scopes []string `json:"scopes"`
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
			"response_type=id_token",
			"client_id=" + p.ClientId,
			"scope=openid email profile",
			"response_mode=form_post",
			"redirect_uri=" + uri,
			"state=" + state.State,
			"nonce=" + newNonce().Nonce,
		}
		// Return the complete authentication URI and the OIDC state
		return p.Endpoints.AuthEndpoint + "?" + strings.Join(parts, "&"), state
	case OAuth2:
		parts = []string{
			"response_type=code",
			"client_id=" + p.ClientId,
			"scope=" + strings.Join(p.Endpoints.Scopes, " "),
			"response_mode=form_post",
			"redirect_uri=" + uri,
			"state=" + state.State,
		}
		// Return the complete authentication URI and the OIDC state
		return p.Endpoints.AuthEndpoint + "?" + strings.Join(parts, "&"), state
	}
	state.Done()
	return "", nil
}

func (p *Provider) processRequest(r *http.Request) (wrapper idwrapper, err error) {
	// Handle different content types in the response
	switch strings.Split(r.Header.Get("Content-Type"), ";")[0] {
	case "application/json":
		// Decode the JSON response into the idwrapper
		err = json.NewDecoder(r.Body).Decode(&wrapper)
		if err != nil {
			return wrapper, err
		}
	case "application/x-www-form-urlencoded":
		// Read the response body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return wrapper, err
		}
		// Parse the response body as URL-encoded form data
		bv, err := url.ParseQuery(string(body))
		if err != nil {
			return wrapper, err
		}
		// Extract the state and id_token from the parsed data
		wrapper.State = bv.Get("state")
		wrapper.IDToken = bv.Get("id_token")
		wrapper.AccessToken = bv.Get("access_token")
		wrapper.Code = bv.Get("code")
	default:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return wrapper, err
		}
		return wrapper, errors.New(string(body))
	}
	return wrapper, nil
}

func (p *Provider) processResponse(r *http.Response) (wrapper idwrapper, err error) {
	// Handle different content types in the response
	switch strings.Split(r.Header.Get("Content-Type"), ";")[0] {
	case "application/json":
		// Decode the JSON response into the idwrapper
		err = json.NewDecoder(r.Body).Decode(&wrapper)
		if err != nil {
			return wrapper, err
		}
	case "application/x-www-form-urlencoded":
		// Read the response body
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return wrapper, err
		}
		// Parse the response body as URL-encoded form data
		bv, err := url.ParseQuery(string(body))
		if err != nil {
			return wrapper, err
		}
		// Extract the state and id_token from the parsed data
		wrapper.State = bv.Get("state")
		wrapper.IDToken = bv.Get("id_token")
		wrapper.AccessToken = bv.Get("access_token")
		wrapper.Code = bv.Get("code")
	default:
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return wrapper, err
		}
		return wrapper, errors.New(string(body))
	}
	return wrapper, nil
}

func (p *Provider) codeToken(r *http.Request) (token idwrapper, err error) {
	// Construct the redirect URI
	uri, _ := url.JoinPath("https://", r.Host, p.RedirectUri)
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
		return token, errors.New(string(body))
	}
	return p.processResponse(res)
}
