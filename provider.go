package oidc

type Providers []Provider

type providertype string

const (
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
