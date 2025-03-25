package oidc

import (
	"context"
	"encoding/json"
	"io"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type Client struct {
	Config ClientConfiguration `json:"config"`
}

type ClientConfiguration struct {
	Domains     []string  `json:"domains"`
	RedirectUri string    `json:"redirect_uri"`
	Providers   Providers `json:"providers"`
}

type Providers []Provider

type Provider struct {
	Id                    string `json:"id"`
	Enabled               bool   `json:"enabled"`
	Name                  string `json:"name"`
	Logo                  string `json:"logo"`
	ClientId              string `json:"clientid"`
	ClientSecret          string `json:"clientsecret"`
	ConfigurationLink     string `json:"configurationlink"`
	SigningKeyLink        string `json:"signinglink"`
	RedirectUri           string `json:"-"`
	Error                 error  `json:"errors"`
	EndpointConfiguration `json:"-"`
	Issuers               []string `json:"issuers"`
}

type EndpointConfiguration struct {
	AuthEndpoint    string   `json:"authorization_endpoint"`
	TokenEndpoint   string   `json:"token_endpoint"`
	SigningEndpoint string   `json:"jwks_uri"`
	Algorithm       []string `json:"id_token_signing_alg_values_supported"`
}

type nonce struct {
	Nonce string
	Done  context.CancelFunc
}

type state struct {
	State       string
	Initiator   string
	RedirectUri string
	Done        context.CancelFunc
}

type IDWrapper struct {
	Token string `json:"id_token"`
}

const letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"

var (
	nonces []*nonce
	states []*state
)

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

func getState(state string) *state {
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

func newState(uri, initiator string) *state {
	ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(time.Minute*5))
	new := &state{
		State:       randString(32),
		Initiator:   initiator,
		Done:        cancel,
		RedirectUri: uri,
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

func (p *Provider) AuthUri(r *http.Request) string {
	parts := []string{
		p.EndpointConfiguration.AuthEndpoint,
		"response_type=code",
		"client_id=" + p.ClientId,
		"scope=openid email",
		"redirect_uri=" + p.RedirectUri,
		"state=" + newState(r.RequestURI, r.RemoteAddr).State,
		"nonce=" + newNonce().Nonce,
	}
	return strings.Join(parts, "&")
}

func (p *Provider) CodeToToken(r *http.Request) (token string, err error) {
	state := getState(r.URL.Query().Get("state"))
	wrapper := IDWrapper{}
	values := url.Values{}
	values.Add("grant_type", "authorization_code")
	values.Add("client_id", p.ClientId)
	values.Add("client_secret", p.ClientSecret)
	values.Add("redirect_uri", p.RedirectUri)
	values.Add("code", r.URL.Query().Get("code"))
	res, err := http.PostForm(p.EndpointConfiguration.TokenEndpoint, values)
	if err != nil {
		return token, err
	}
	switch res.Header.Get("Content-Type") {
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
		wrapper.Token = bv.Get("id_token")
	}
	log.Print(state)
	return wrapper.Token, err
}
