# OIDC Library for Go

A lightweight, secure OpenID Connect (OIDC) client library for Go, designed to handle multiple identity providers with automatic discovery, JWT verification, and robust security features.

## Features

- **Automatic Provider Discovery**: Fetches OIDC endpoints and public keys from well-known configuration links.
- **Multi-Provider Support**: Configure multiple identity providers (Google, Microsoft, etc.) and handle them with a single client.
- **JWT Verification**: Robust RS256 signature verification for ID tokens.
- **Security Protections**:
    - **State Management**: Prevents CSRF attacks with random state tokens and automatic timeouts.
    - **Nonce Verification**: Protects against replay attacks.
    - **IP Consistency Check**: Ensures the authentication initiator and callback requestor share the same IP address.
- **Session Support**: Easily integrate with your application's session management via a customizable callback.

## Installation

```bash
go get github.com/yay101/oidc
```

## Quick Start

### 1. Initialize the Client

```go
import (
    "log/slog"
    "github.com/yay101/oidc"
)

func main() {
    // Define OIDC Providers
    providers := oidc.Providers{
        {
            Id:                "google",
            Enabled:           true,
            Name:              "Google",
            ClientId:          "your-client-id",
            ClientSecret:      "your-client-secret",
            ConfigurationLink: "https://accounts.google.com/.well-known/openid-configuration",
            RedirectUri:       "/auth/callback",
            Scopes:            []string{"openid", "profile", "email"},
        },
    }

    // Initialize Client
    client := oidc.NewClient(
        []string{"localhost:8080"}, // Allowed domains
        providers,
        "/auth/callback",           // Auth path
        "/login",                   // Login path
        slog.Default(),
    )

    // Set successful login callback
    client.Callback = func(accessToken, refreshToken *string, expiry *int, idToken oidc.IDToken) (bool, *http.Cookie) {
        // Create your application session here
        cookie := &http.Cookie{
            Name:  "my_session",
            Value: idToken.Subject,
            Path:  "/",
        }
        return true, cookie
    }

    // Register Handlers
    http.Handle("/auth/provider/", client.ProviderHandler)
    http.Handle("/auth/callback", client.RedirectHandler)
    
    http.ListenAndServe(":8080", nil)
}
```

### 2. Login Page Integration

In your login template, you can loop through the providers to display login buttons:

```html
{{range .Providers}}
    <a href="/auth/provider/{{.Id}}">Sign in with {{.Name}}</a>
{{end}}
```

## Security Design

### State & Nonce
The library generates 32-character random strings for both `state` and `nonce`. These are stored in-memory with a 5-minute expiration context. The `state` is verified during the callback, and the `nonce` is validated against the claim in the ID Token.

### IP Verification
To prevent session hijacking during the OIDC flow, the library records the IP address of the user who initiates the login. The callback handler verifies that the IP (supporting `X-Forwarded-For`, `X-Real-IP`, etc.) matches the initiator.

### JWT Handling
ID Tokens are parsed and verified using the provider's public keys. The library automatically rotates keys every 12 hours or performs an immediate refresh if a signature verification fails with an unknown Key ID (KID).

## License
MIT
