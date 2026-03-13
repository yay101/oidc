package oidc

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Providers is a collection of OIDC providers.
type Providers []Provider

// Provider defines the configuration and runtime state for an OpenID Connect (OIDC) identity provider.
type Provider struct {
	// Id is a unique identifier for the provider (e.g., "google").
	Id string `json:"id"`
	// Enabled indicates whether the provider is active.
	Enabled bool `json:"enabled"`
	// Name is the display name for the provider.
	Name string `json:"name"`
	// Logo is a URL or base64 string for the provider's icon.
	Logo string `json:"logo"`
	// Default marks this provider as the fallback choice.
	Default bool `json:"default"`
	// ClientId is the OAuth2 Client ID issued by the provider.
	ClientId string `json:"clientid"`
	// ClientSecret is the OAuth2 Client Secret issued by the provider.
	ClientSecret string `json:"clientsecret"`
	// ConfigurationLink is the OIDC Discovery URL (usually ends in .well-known/openid-configuration).
	ConfigurationLink string `json:"configurationlink"`
	// RedirectUri is the application path where the provider sends the auth code.
	RedirectUri string `json:"redirecturi"`
	// Error captures any initialization or discovery errors.
	Error error `json:"errors"`
	// Scopes defines requested permissions (default: openid, profile, email).
	Scopes []string `json:"scopes"`
	// Endpoints stores the discovered OIDC URLs.
	Endpoints EndpointConfiguration `json:"-"`
	// Issuers lists valid issuer strings for this provider.
	Issuers []string `json:"issuers"`
	// Keys caches the provider's public keys for signature verification.
	Keys []pubkey `json:"-"`
}

// EndpointConfiguration holds the discovered OIDC service endpoints.
type EndpointConfiguration struct {
	// AuthEndpoint is the URL for the authorization request.
	AuthEndpoint string `json:"authorization_endpoint"`
	// TokenEndpoint is the URL for the token exchange request.
	TokenEndpoint string `json:"token_endpoint"`
	// SigningEndpoint is the URL for the JWKS (JSON Web Key Set).
	SigningEndpoint string `json:"jwks_uri"`
	// Algorithm lists supported JWS algorithms.
	Algorithm []string `json:"id_token_signing_alg_values_supported"`
	// ClaimsSupported lists claims the OP can provide.
	ClaimsSupported []string `json:"claims_supported"`
	// GrantTypes lists supported OAuth2 grant types.
	GrantTypes []string `json:"grant_types_supported"`
}

// AuthUri generates the provider's authorization URL and a unique session state.
func (p *Provider) AuthUri(r *http.Request) (string, *oidcstate) {
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
		host = useraddr // Fallback for addresses without ports
	}

	if len(p.Scopes) == 0 {
		p.Scopes = []string{"openid", "profile", "email"}
	}

	// Create OIDC state for CSRF protection
	state := newState(p, r.Referer(), host)

	// Determine scheme (prefer HTTPS, fallback to HTTP for local dev)
	scheme := "https://"
	if r.TLS == nil {
		if strings.HasPrefix(r.Host, "localhost") || strings.HasPrefix(r.Host, "127.0.0.1") {
			scheme = "http://"
		}
	}

	// Construct callback URL
	uri, _ := url.JoinPath(scheme, r.Host, p.RedirectUri)

	params := url.Values{}
	params.Add("response_type", "code")
	params.Add("client_id", p.ClientId)
	params.Add("scope", strings.Join(p.Scopes, " "))
	params.Add("response_mode", "form_post")
	params.Add("redirect_uri", uri)
	params.Add("state", state.State)
	params.Add("nonce", newNonce().Nonce)

	return p.Endpoints.AuthEndpoint + "?" + params.Encode(), state
}

// processResponse handles unmarshaling the token response from the identity provider.
func (p *Provider) processResponse(r *http.Response) (wrapper idwrapper, err error) {
	contentType := strings.Split(r.Header.Get("Content-Type"), ";")[0]

	switch contentType {
	case "application/json":
		err = json.NewDecoder(r.Body).Decode(&wrapper)
		return wrapper, err
	case "application/x-www-form-urlencoded":
		body, err := io.ReadAll(r.Body)
		if err != nil {
			return wrapper, err
		}
		bv, err := url.ParseQuery(string(body))
		if err != nil {
			return wrapper, err
		}
		if val := bv.Get("expires_in"); val != "" {
			if i, err := strconv.Atoi(val); err == nil {
				wrapper.ExpiresIn = &i
			}
		}
		if val := bv.Get("id_token"); val != "" {
			wrapper.IDToken = &val
		}
		if val := bv.Get("access_token"); val != "" {
			wrapper.AccessToken = &val
		}
		if val := bv.Get("refresh_token"); val != "" {
			wrapper.RefreshToken = &val
		}
		return wrapper, nil
	default:
		body, _ := io.ReadAll(r.Body)
		return wrapper, fmt.Errorf("unexpected content type %s: %s", contentType, string(body))
	}
}

// codeToken performs the authorization code exchange for an access token and ID token.
func (p *Provider) codeToken(r *http.Request) (token idwrapper, err error) {
	uri, _ := url.JoinPath("https://", r.Host, p.RedirectUri)

	values := url.Values{}
	values.Add("grant_type", "authorization_code")
	values.Add("client_id", p.ClientId)
	values.Add("client_secret", p.ClientSecret)
	values.Add("redirect_uri", uri)
	values.Add("code", r.FormValue("code"))

	res, err := http.PostForm(p.Endpoints.TokenEndpoint, values)
	if err != nil {
		return token, err
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(res.Body)
		return token, fmt.Errorf("token request failed (%d): %s", res.StatusCode, string(body))
	}
	return p.processResponse(res)
}
