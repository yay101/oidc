package oidc

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

type Client struct {
	// Config holds the configuration for the OIDC client
	Config ClientConfiguration `json:"configuration"`
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
	Domains []string `json:"domains"`
	// AuthPath is the URL path for authentication endpoint
	AuthPath string `json:"auth_path"`
	// LoginPath is the URL path for the login page
	LoginPath string `json:"login_path"`
	// Providers contains the list of configured OIDC providers
	Providers Providers `json:"providers"`
}

type Providers []Provider

type Provider struct {
	Id                string                `json:"id"`
	Enabled           bool                  `json:"enabled"`
	Name              string                `json:"name"`
	Logo              string                `json:"logo"`
	ClientId          string                `json:"clientid"`
	ClientSecret      string                `json:"clientsecret"`
	ConfigurationLink string                `json:"configurationlink"`
	RedirectUri       string                `json:"redirecturi"`
	Error             error                 `json:"errors"`
	Endpoints         EndpointConfiguration `json:"-"`
	Issuers           []string              `json:"issuers"`
	Keys              []pubkey              `json:"-"`
}

type EndpointConfiguration struct {
	AuthEndpoint    string   `json:"authorization_endpoint"`
	TokenEndpoint   string   `json:"token_endpoint"`
	SigningEndpoint string   `json:"jwks_uri"`
	Algorithm       []string `json:"id_token_signing_alg_values_supported"`
	ClaimsSupported []string `json:"claims_supported"`
	GrantTypes      []string `json:"grant_types_supported"`
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
	Token string `json:"id_token"`
	State string `json:"state"`
}

type secTime time.Time

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var (
	nonces []*nonce
	states []*oidcstate
)

func (s *secTime) UnmarshalJSON(data []byte) error {
	secs, err := strconv.ParseInt(string(data), 10, 64)
	if err != nil {
		return err
	}
	*s = secTime(time.Unix(secs, 0))
	return nil
}

func randString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}

func getNonce(nonce string) bool {
	for _, n := range nonces {
		if n.Nonce == nonce {
			n.Done()
			return true
		}
	}
	return false
}

func getState(state string) *oidcstate {
	for _, s := range states {
		if s.State == state {
			return s
		}
	}
	return nil
}

func newNonce() *nonce {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute*5))
	new := &nonce{
		Nonce: randString(32),
		Done:  cancel,
	}
	nonces = append(nonces, new)
	go func() {
		<-ctx.Done()
		for i, n := range nonces {
			if n == new {
				nonces = append(nonces[:i], nonces[i+1:]...)
			}
		}
	}()
	return new
}

func newState(provider *Provider, uri, initiator string) *oidcstate {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute*5))
	new := &oidcstate{
		State:       randString(32),
		Initiator:   initiator,
		Done:        cancel,
		RedirectUri: uri,
		Provider:    provider,
	}
	states = append(states, new)
	go func() {
		<-ctx.Done()
		for i, s := range states {
			if s == new {
				states = append(states[:i], states[i+1:]...)
			}
		}
	}()
	return new
}

func (p *Provider) AuthUri(r *http.Request) (string, *oidcstate) {
	state := newState(p, r.Referer(), r.Host)
	uri, _ := url.JoinPath("https://", r.Host, p.RedirectUri)
	parts := []string{
		"response_type=code",
		"client_id=" + p.ClientId,
		"scope=openid%20email",
		"redirect_uri=" + url.QueryEscape(uri),
		"state=" + url.QueryEscape(state.State),
		"nonce=" + url.QueryEscape(newNonce().Nonce),
	}
	return p.Endpoints.AuthEndpoint + "?" + strings.Join(parts, "&"), state
}

func (p *Provider) codeToken(r *http.Request) (token idwrapper, err error) {
	uri, _ := url.JoinPath("https://", r.Host, p.RedirectUri)
	wrapper := idwrapper{}
	values := url.Values{}
	values.Add("grant_type", "authorization_code")
	values.Add("client_id", p.ClientId)
	values.Add("client_secret", p.ClientSecret)
	values.Add("redirect_uri", uri)
	values.Add("code", r.URL.Query().Get("code"))
	res, err := http.PostForm(p.Endpoints.TokenEndpoint, values)
	if err != nil {
		log.Print(err)
		return token, err
	}
	switch strings.Split(res.Header.Get("Content-Type"), ";")[0] {
	case "application/json":
		err = json.NewDecoder(res.Body).Decode(&wrapper)
	case "application/x-www-form-urlencoded":
		body, err := io.ReadAll(res.Body)
		if err != nil {
			return token, err
		}
		bv, err := url.ParseQuery(string(body))
		if err != nil {
			return token, err
		}
		wrapper.State = bv.Get("state")
		wrapper.Token = bv.Get("id_token")
	default:
		body, _ := io.ReadAll(res.Body)
		log.Print(string(body))
	}
	return wrapper, err
}
