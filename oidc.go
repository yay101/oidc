package oidc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"time"
)

// NewClient initializes a new OIDC Client with the provided parameters.
// It sets up automatic key rotation and creates handlers for initiating auth and processing callbacks.
func NewClient(domains []string, providers Providers, authpath string, loginpath string, logger *slog.Logger) *Client {
	if logger == nil {
		lj = slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{AddSource: true}))
	} else {
		lj = logger
	}

	client := &Client{
		Config: ClientConfiguration{
			Domains:   domains,
			AuthPath:  authpath,
			LoginPath: loginpath,
			Providers: providers,
		},
	}

	// Validate configuration for all providers and set defaults
	for i := range providers {
		if providers[i].RedirectUri == "" {
			providers[i].RedirectUri = client.Config.AuthPath
		}
		err := providers[i].checkConfigurationLink()
		if err != nil {
			lj.Error(fmt.Sprintf("failed to validate configuration link for provider %s: %v", providers[i].Id, err.Error()))
			providers[i].Error = err
		}
	}

	// Background routine for automatic JWKS (Public Keys) rotation
	go func() {
		tick := time.NewTicker(12 * time.Hour)
		for {
			for i := range providers {
				providers[i].getKeys()
			}
			<-tick.C
		}
	}()

	// ProviderHandler initiates the OIDC flow by redirecting to the chosen provider's Auth URI.
	client.ProviderHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !slices.Contains(client.Config.Domains, r.Host) {
			lj.Warn("request host not in allowed domains", "host", r.Host)
			http.Redirect(w, r, r.Referer(), 302)
			return
		}

		id := r.PathValue("id")
		if id == "" || id == "default" {
			if len(client.Config.Providers) > 0 {
				id = client.Config.Providers[0].Id
			}
			for i := range client.Config.Providers {
				if client.Config.Providers[i].Default {
					id = client.Config.Providers[i].Id
					break
				}
			}
		}

		for i := range client.Config.Providers {
			if client.Config.Providers[i].Id == id {
				url, state := client.Config.Providers[i].AuthUri(r)
				if state == nil {
					http.Error(w, "failed to generate authentication state", 500)
					return
				}
				http.Redirect(w, r, url, 302)
				return
			}
		}
		http.Error(w, "OIDC provider not found", 404)
	})

	// RedirectHandler processes the callback from the OIDC provider.
	client.RedirectHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()

		state := &oidcstate{}
		if r.Form.Has("state") {
			state = getState(r.FormValue("state"))
		}

		if r.Form.Has("error") {
			lj.Error("OIDC provider returned an error", "error", r.FormValue("error"), "desc", r.FormValue("error_description"))
			http.Redirect(w, r, client.Config.LoginPath+"?error="+url.PathEscape(r.FormValue("error_description")), http.StatusFound)
			return
		}

		if state == nil {
			lj.Error("no valid state found for callback request")
			http.Redirect(w, r, client.Config.LoginPath+"?error="+url.PathEscape("Session expired or invalid state."), http.StatusFound)
			return
		}
		defer state.Done()

		wrapper, err := state.Provider.codeToken(r)
		if err != nil {
			lj.Error("token exchange failed", "error", err)
			http.Redirect(w, r, client.Config.LoginPath+"?error="+url.PathEscape(err.Error()), http.StatusFound)
			return
		}

		IdToken := IDToken{
			Initiator: state.Initiator,
		}

		// Robust IP consistency check
		clientIP := getClientIP(r)
		if clientIP != state.Initiator {
			lj.Warn("IP mismatch during callback", "initiator", state.Initiator, "current", clientIP)
			http.Redirect(w, r, client.Config.LoginPath+"?error="+url.PathEscape("Security check failed: IP address changed."), http.StatusFound)
			return
		}

		if wrapper.IDToken != nil {
			parts := strings.Split(*wrapper.IDToken, ".")
			if len(parts) != 3 {
				lj.Error("invalid ID Token format")
				http.Redirect(w, r, client.Config.LoginPath+"?error="+url.PathEscape("Invalid token format."), http.StatusFound)
				return
			}

			hb, err := base64.RawURLEncoding.DecodeString(parts[0])
			pb, err := base64.RawURLEncoding.DecodeString(parts[1])
			if err != nil {
				lj.Error("failed to decode JWT segments", "error", err)
				http.Redirect(w, r, client.Config.LoginPath+"?error="+url.PathEscape("Token decoding failed."), http.StatusFound)
				return
			}

			h := tokenheader{}
			if err = json.Unmarshal(hb, &h); err != nil {
				lj.Error("failed to unmarshal token header", "error", err)
				http.Redirect(w, r, client.Config.LoginPath+"?error="+url.PathEscape(err.Error()), http.StatusFound)
				return
			}

			if err = json.Unmarshal(pb, &IdToken); err != nil {
				lj.Error("failed to unmarshal token payload", "error", err)
				http.Redirect(w, r, client.Config.LoginPath+"?error="+url.PathEscape(err.Error()), http.StatusFound)
				return
			}

			if time.Time(IdToken.IssuedAt).After(time.Now().Add(5 * time.Minute)) {
				lj.Error("token issued in the future")
				http.Redirect(w, r, client.Config.LoginPath+"?error="+url.PathEscape("Token timing invalid."), http.StatusFound)
				return
			}

			if time.Time(IdToken.Expiration).Before(time.Now()) {
				lj.Error("token expired")
				http.Redirect(w, r, client.Config.LoginPath+"?error="+url.PathEscape("Token expired."), http.StatusFound)
				return
			}

			if !getNonce(IdToken.Nonce) {
				lj.Error("nonce verification failed")
				http.Redirect(w, r, client.Config.LoginPath+"?error="+url.PathEscape("Security check failed: Nonce mismatch."), 302)
				return
			}

			verified := false
			cachedKeys := state.Provider.GetCachedKeys()
			for range 2 {
				for _, key := range cachedKeys {
					if key.Id != h.Kid {
						continue
					}
					ok, err := verifyRS256Signature(*wrapper.IDToken, key.Key)
					if ok && err == nil {
						verified = true
						break
					}
				}
				if verified {
					break
				}
				state.Provider.getKeys()
				cachedKeys = state.Provider.GetCachedKeys()
			}

			if !verified {
				lj.Error("failed to verify ID Token signature")
				http.Redirect(w, r, client.Config.LoginPath+"?error="+url.PathEscape("Token signature verification failed."), 302)
				return
			}
		}

		if ok, cookie := client.Callback(wrapper.AccessToken, wrapper.RefreshToken, wrapper.ExpiresIn, IdToken); ok {
			cookie.Domain = r.Host
			http.SetCookie(w, cookie)

			finalTarget := state.RedirectUri
			if strings.Contains(finalTarget, client.Config.AuthPath) || strings.Contains(finalTarget, client.Config.LoginPath) {
				finalTarget = "/"
			}
			http.Redirect(w, r, finalTarget, 302)
			return
		}
	})

	return client
}

func getClientIP(r *http.Request) string {
	for _, header := range []string{"X-Forwarded-For", "Forwarded-For", "X-Real-IP"} {
		if val := r.Header.Get(header); val != "" {
			if strings.Contains(val, ",") {
				val = strings.TrimSpace(strings.Split(val, ",")[0])
			}
			if host, _, err := net.SplitHostPort(val); err == nil {
				return host
			}
			return val
		}
	}
	if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		return host
	}
	return r.RemoteAddr
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
	for _, provider := range *p {
		if provider.Enabled {
			enabled = append(enabled, provider)
		}
	}
	return enabled
}

func (p *Provider) checkConfigurationLink() (err error) {
	resp, err := http.Get(p.ConfigurationLink)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return errors.New("discovery endpoint returned status: " + resp.Status)
	}

	err = json.NewDecoder(resp.Body).Decode(&p.Endpoints)
	if err != nil {
		return errors.New("failed to decode OIDC discovery metadata")
	}
	return nil
}
