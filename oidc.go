package oidc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"
)

func NewClient(domains []string, providers Providers, authpath string, loginpath string, logger *slog.Logger) *Client {
	if logger == nil {
		lj = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{AddSource: true}))
	} else {
		lj = logger
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
		err := providers[i].checkConfigurationLink()
		if err != nil {
			lj.Error(fmt.Sprintf("failed to validate configuration link %v", err.Error()))
			providers[i].Error = err
		}
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
				if state == nil {
					http.Error(w, "could not generate a valid state, should only occur when we can't determine the incoming request address", 500)
					return
				}
				// Redirect user to the authorization endpoint
				http.Redirect(w, r, url, 302)
				return
			}
		}
	})

	// Set the redirect handler function for the client (handles OAuth callback)
	client.RedirectHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Parse form data from the request
		r.ParseForm()
		// Retrieve state cookie from the request
		state := &oidcstate{}
		if r.Form.Has("state") {
			state = getState(r.FormValue("state"))
		}
		if r.Form.Has("error") {
			lj.Error(r.FormValue("error_description"))
			http.Redirect(w, r, client.Config.LoginPath+"?error="+url.PathEscape(r.FormValue("error_description")), http.StatusFound)
			return
		}
		if state == nil {
			lj.Error("no state with request")
			// Redirect to login page on error
			http.Redirect(w, r, client.Config.LoginPath+"?error="+url.PathEscape("No state  with request!"), http.StatusFound)
			return
		}
		// Kill state either way by the end of this process
		defer state.Done()
		// Process the code
		wrapper, err := state.Provider.codeToken(r)
		if err != nil {
			lj.Error(err.Error())
			// Redirect to login page on error
			http.Redirect(w, r, client.Config.LoginPath+"?error="+url.PathEscape(err.Error()), http.StatusFound)
			return
		}
		// Initialize token header and ID token structures
		h := tokenheader{}
		AccessToken := wrapper.AccessToken
		RefreshToken := wrapper.RefreshToken
		Expiry := wrapper.ExpiresIn
		IdToken := IDToken{
			Initiator: state.Initiator,
		}
		//check the ip address is the same as the original requestor
		xfwdHost, _, _ := net.SplitHostPort(r.Header.Get("X-Forwarded-For"))
		fwdHost, _, _ := net.SplitHostPort(r.Header.Get("Forwarded-For"))
		realIPHost, _, _ := net.SplitHostPort(r.Header.Get("X-Real-IP"))
		remoteHost, _, _ := net.SplitHostPort(r.RemoteAddr)
		// Trigger error if none of the potential host sources match the initiator
		if xfwdHost != state.Initiator && fwdHost != state.Initiator && realIPHost != state.Initiator && remoteHost != state.Initiator {
			http.Redirect(w, r, client.Config.LoginPath+"?error="+url.PathEscape("Bad location, did your IP change?"), http.StatusFound)
			return
		}
		if wrapper.IDToken != nil {
			// Make sure IDToken has the right number of splits
			if count := strings.Count(*wrapper.IDToken, "."); count != 2 {
				lj.Error("invalid jwt format", "extra", strconv.Itoa(count)+" . (want 2)")
				http.Redirect(w, r, client.Config.LoginPath+"?error="+url.PathEscape("Invalid token format."), http.StatusFound)
				return
			}
			// Split the JWT token into its components
			parts := strings.Split(*wrapper.IDToken, ".")
			if len(parts) != 3 {
				lj.Error("invalid token format", "extra", strconv.Itoa(len(parts))+" parts (want 3)")
				http.Redirect(w, r, client.Config.LoginPath+"?error="+url.PathEscape("Invalid token format."), http.StatusFound)
				return
			}
			// Decode header and payload from base64
			hb, err := base64.RawURLEncoding.DecodeString(parts[0])
			if err != nil {
				lj.Info("invalid characters in header", "extra", err.Error())
				http.Redirect(w, r, client.Config.LoginPath+"?error="+url.PathEscape("Invalid token format."), http.StatusFound)
				return
			}
			// Decode Payload
			pb, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				lj.Info("invalid characters in payload", "extra", err.Error())
				http.Redirect(w, r, client.Config.LoginPath+"?error="+url.PathEscape(err.Error()), http.StatusFound)
				return
			}
			// Unmarshal header JSON
			err = json.Unmarshal(hb, &h)
			if err != nil {
				lj.Info("cannot unmarshal header", "extra", err.Error())
				// Redirect to login page on error
				http.Redirect(w, r, client.Config.LoginPath+"?error="+url.PathEscape(err.Error()), http.StatusFound)
				return
			}

			// Unmarshal payload JSON
			err = json.Unmarshal(pb, &IdToken)
			if err != nil {
				lj.Info("cannot unmarshal payload", "extra", err.Error())
				// Redirect to login page on error
				http.Redirect(w, r, client.Config.LoginPath+"?error="+url.PathEscape(err.Error()), http.StatusFound)
				return
			}

			// Check if token is issued in the future (potential clock skew)
			if time.Time(IdToken.IssuedAt).After(time.Now().Add(5 * time.Minute)) {
				lj.Info("token issued in the future")
				// Redirect to login page on error
				http.Redirect(w, r, client.Config.LoginPath+"?error="+url.PathEscape("Token issued in the future!"), http.StatusFound)
				return
			}

			// Check if token is expired
			if time.Time(IdToken.Expiration).Before(time.Now()) {
				lj.Info("token has expired")
				// Redirect to login page on error
				http.Redirect(w, r, client.Config.LoginPath+"?error="+url.PathEscape("Token already expired."), http.StatusFound)
				return
			}

			// Verify nonce to prevent replay attacks
			if !getNonce(IdToken.Nonce) {
				lj.Info("replay protection triggered.")
				http.Redirect(w, r, client.Config.LoginPath+"?error="+url.PathEscape("Replay protection triggered."), 302)
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
					ok, err := verifyRS256Signature(*wrapper.IDToken, state.Provider.Keys[i].Key)
					if !ok || err != nil {
						lj.Info("could not verify the signature of the token")
						http.Redirect(w, r, client.Config.LoginPath+"?error="+url.PathEscape("Could not verify the signature of your token:"+err.Error()), 302)
						return
					}
				}
				// Refresh keys if signature verification failed
				state.Provider.getKeys()
			}
		}
		// Call the client's callback function
		if ok, cookie := client.Callback(AccessToken, RefreshToken, Expiry, IdToken); ok {
			// Set the cookie domain to the initiator
			cookie.Domain = r.Host
			http.SetCookie(w, cookie)
			if strings.Contains(state.RedirectUri, client.Config.AuthPath) || strings.Contains(state.RedirectUri, client.Config.LoginPath) {
				log.Print(state.RedirectUri)
				state.RedirectUri = "/"
				log.Print(r.Host)
			}
			// Redirect to the original redirect URI
			http.Redirect(w, r, state.RedirectUri, 302)
			return
		}
	})
	// Return the fully configured client
	return client
}

func (c *Client) GetProvider(id string) *Provider {
	if len(c.Config.Providers) == 1 {
		return &c.Config.Providers[0]
	}
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

func (p *Provider) checkConfigurationLink() (err error) {
	// Send HTTP GET request to the configuration link
	resp, err := http.Get(p.ConfigurationLink)
	if err != nil {
		return err
	}
	if resp.StatusCode != 200 {
		// Check if response status code is not 200 OK
		return errors.New("got response code " + resp.Status)
	}
	// Decode JSON response body into Provider Endpoints
	err = json.NewDecoder(resp.Body).Decode(&p.Endpoints)
	if err != nil {
		// Handle JSON decoding error
		return errors.New("error decoding configuration link")
	}
	return nil
}
