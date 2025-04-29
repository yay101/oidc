package oidc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"log"
	"log/slog"
	"net/http"
	"os"
	"slices"
	"strings"
	"time"
)

func NewClient(domains []string, providers []Provider, authpath string, loginpath string, logger *slog.Logger) *Client {
	if logger == nil {
		lj = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{AddSource: true}))
	}
	// Initialize a new client with the provided configuration
	client := &Client{
		Config: ClientConfiguration{
			Domains:   domains,
			AuthPath:  authpath,
			LoginPath: loginpath,
			Providers: providers,
		},
	}

	// Validate all the providers that are passed to the new client
	for i := range providers {
		// Set default redirect URI if none is provided
		if providers[i].RedirectUri == "" {
			providers[i].RedirectUri = client.Config.AuthPath
		}
		// Validate each provider's configuration
		providers[i].validate()
	}

	// Run getkeys regularly to prevent stale signatures
	go func() {
		// Create a ticker that triggers every 12 hours
		tick := time.NewTicker(12 * time.Hour)
		for {
			// Fetch keys for all providers
			for i := range providers {
				providers[i].getKeys()
			}
			// Wait for the next tick (after initial key fetch)
			// Tick at the end so getkeys is always ran on startup
			<-tick.C
		}
	}()

	// Set up the provider handler to initiate authentication
	client.ProviderHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !slices.Contains(client.Config.Domains, r.Host) {
			http.Redirect(w, r, r.Referer(), 302)
			return
		}
		// Extract provider ID from the request path
		id := r.PathValue("id")
		// Find the matching provider by ID
		for i := range client.Config.Providers {
			if client.Config.Providers[i].Id == id {
				// Generate authorization URL and state
				url, state := client.Config.Providers[i].AuthUri(r)
				// Set state cookie for later verification
				http.SetCookie(w, &http.Cookie{Name: "state", Value: state.State, Path: client.Config.AuthPath, Expires: time.Now().Add(5 * time.Minute), Secure: true})
				// Redirect user to the authorization endpoint
				http.Redirect(w, r, url, 302)
				return
			}
		}
	})

	// Set the redirect handler function for the client (handles OAuth callback)
	client.RedirectHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Retrieve state cookie from the request
		cookie, err := r.Cookie("state")
		if err != nil {
			log.Print("no state cookie with request")
			// Redirect to login page on error
			http.Redirect(w, r, client.Config.LoginPath, http.StatusFound)
			return
		}

		// Get state object from cookie value
		state := getState(cookie.Value)

		// Parse form data from the request
		r.ParseForm()

		// Process authorization code if present and state is valid
		if r.Form.Has("code") && state != nil {
			// Exchange code for token
			wrapper, err := state.Provider.codeToken(r)
			if err != nil {
				state.Done()
				http.SetCookie(w, &http.Cookie{Name: "Login-Error", Path: "/login", Value: err.Error()})
				// Redirect to login page on error
				http.Redirect(w, r, client.Config.LoginPath, http.StatusFound)
				return
			}

			// Split the JWT token into its components
			parts := strings.Split(wrapper.Token, ".")
			if len(parts) != 3 {
				state.Done()
				http.SetCookie(w, &http.Cookie{Name: "Login-Error", Path: "/login", Value: "Invalid token format."})
				http.Redirect(w, r, client.Config.LoginPath, http.StatusFound)
				return
			}
			// Decode header and payload from base64
			hb, err := base64.RawURLEncoding.DecodeString(parts[0])
			if err != nil {
				http.SetCookie(w, &http.Cookie{Name: "Login-Error", Path: "/login", Value: err.Error()})
				http.Redirect(w, r, client.Config.LoginPath, http.StatusFound)
				return
			}
			pb, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				http.SetCookie(w, &http.Cookie{Name: "Login-Error", Path: "/login", Value: err.Error()})
				http.Redirect(w, r, client.Config.LoginPath, http.StatusFound)
				return
			}

			// Initialize token header and ID token structures
			h := tokenheader{}
			p := IDToken{
				Initiator: state.Initiator,
			}

			// Unmarshal header JSON
			err = json.Unmarshal(hb, &h)
			if err != nil {
				log.Print(err)
				http.SetCookie(w, &http.Cookie{Name: "Login-Error", Path: "/login", Value: err.Error()})
				// Redirect to login page on error
				http.Redirect(w, r, client.Config.LoginPath, http.StatusFound)
				return
			}

			// Unmarshal payload JSON
			err = json.Unmarshal(pb, &p)
			if err != nil {
				log.Print(err)
				http.SetCookie(w, &http.Cookie{Name: "Login-Error", Path: "/login", Value: err.Error()})
				// Redirect to login page on error
				http.Redirect(w, r, client.Config.LoginPath, http.StatusFound)
				return
			}

			// Check if token is issued in the future (potential clock skew)
			if time.Time(p.IssuedAt).After(time.Now().Add(5 * time.Minute)) {
				http.SetCookie(w, &http.Cookie{Name: "Login-Error", Path: "/login", Value: "Token issued in the future!"})
				// Redirect to login page on error
				http.Redirect(w, r, client.Config.LoginPath, http.StatusFound)
				return
			}

			// Check if token is expired
			if time.Time(p.Expiration).Before(time.Now()) {
				log.Print("Expired.")
				http.SetCookie(w, &http.Cookie{Name: "Login-Error", Path: "/login", Value: "Token already expired."})
				// Redirect to login page on error
				http.Redirect(w, r, client.Config.LoginPath, http.StatusFound)
				return
			}

			// Verify nonce to prevent replay attacks
			if !getNonce(p.Nonce) {
				http.SetCookie(w, &http.Cookie{Name: "Login-Error", Path: "/login", Value: "Replay protection triggered."})
				http.Redirect(w, r, client.Config.LoginPath, 302)
				return
			}

			// Try to verify signature twice, refreshing keys if first attempt fails
			for range 2 {
				// Check each key from the provider
				for i := range state.Provider.Keys {
					// Skip keys that don't match the key ID in the token header
					if state.Provider.Keys[i].Id != h.Kid {
						continue
					}

					// Verify the RS256 signature using the provider's public key
					ok, err := verifyRS256Signature(wrapper.Token, state.Provider.Keys[i].Key)
					if !ok || err != nil {
						http.SetCookie(w, &http.Cookie{Name: "Login-Error", Path: "/login", Value: "Could not verify the signature of your token:" + err.Error()})
						http.Redirect(w, r, client.Config.LoginPath, 302)
						return
					} else {
						// If signature is valid, call the client's callback function
						if ok, cookie := client.Callback(p); ok {
							// Set the cookie domain to the initiator
							cookie.Domain = state.Initiator
							http.SetCookie(w, cookie)
							redirect, _ := r.Cookie("Login-Redirect")
							if redirect != nil {
								state.RedirectUri = redirect.Value
							}
							// Redirect to the original redirect URI
							http.Redirect(w, r, state.RedirectUri, 302)
							return
						}
					}
				}
				// Refresh keys if signature verification failed
				state.Provider.getKeys()
			}
		}
	})
	// Return the fully configured client
	return client
}

func (c *Client) GetProvider(id string) *Provider {
	for i := range c.Config.Providers {
		if c.Config.Providers[i].Id == id || c.Config.Providers[i].Name == id {
			return &c.Config.Providers[i]
		}
	}
	return nil
}

func (p *Providers) Enabled() (enabled []Provider) {
	// Iterate through all providers in the collection
	for _, provider := range *p {
		// Only add providers that have the Enabled flag set to true
		if provider.Enabled {
			enabled = append(enabled, provider)
		}
	}
	// Return the slice of enabled providers
	return enabled
}

func (p *Provider) validate() (err error) {
	// Check if the logo link is valid and accessible
	p.checkLogoLink()
	// Verify the configuration link and decode the provider endpoints
	p.checkConfigurationLink()
	// If any errors were encountered during validation, return them
	if p.Error != nil {
		return p.Error
	}
	// Return nil if validation succeeded
	return nil
}

func (p *Provider) checkConfigurationLink() {
	// Send HTTP GET request to the configuration link
	resp, err := http.Get(p.ConfigurationLink)
	if err != nil {
		// Handle error from GET request
		p.Error = errors.Join(err, errors.New("error getting configuration link"))
	}
	if resp.StatusCode != 200 {
		// Check if response status code is not 200 OK
		p.Error = errors.Join(err, errors.New("got response code "+resp.Status))
	}
	// Decode JSON response body into Provider Endpoints
	err = json.NewDecoder(resp.Body).Decode(&p.Endpoints)
	if err != nil {
		// Handle JSON decoding error
		p.Error = errors.Join(err, errors.New("error decoding configuration link"))
	}
}

func (p *Provider) checkLogoLink() {
	// Send HTTP GET request to the logo URL
	resp, err := http.Get(p.Logo)
	if err != nil {
		// Handle error from GET request
		p.Error = errors.Join(err, errors.New("error getting logo from link"))
	}
	if resp.StatusCode != 200 {
		// Check if response status code is not 200 OK
		p.Error = errors.Join(err, errors.New("got response code "+resp.Status))
	}
}
