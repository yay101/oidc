package oidc

import (
	"encoding/json"
	"errors"
	"net/http"
)

type Server struct {
}

func NewClient(domains []string, redirectUri string, providers []Provider) *Client {
	client := &Client{
		Config: ClientConfiguration{
			Domains:     domains,
			RedirectUri: redirectUri,
			Providers:   providers,
		},
	}
	for _, provider := range providers {
		provider.Error = provider.Validate()
	}
	return client
}

func NewServer() *Server {
	return &Server{}
}

func (c *Client) GetProvider(id string) *Provider {
	for i := range c.Config.Providers {
		if c.Config.Providers[i].Id == id || c.Config.Providers[i].Name == id {
			return &c.Config.Providers[i]
		}
	}
	return nil
}

func (c *Client) Providers() []Provider {
	return c.Config.Providers
}

func (p *Providers) Enabled() []Provider {
	var enabled []Provider
	for _, provider := range *p {
		if provider.Enabled {
			enabled = append(enabled, provider)
		}
	}
	return enabled
}

func (p *Provider) Validate() (err error) {
	return errors.Join(err, p.checkLogoLink(), p.checkConfigurationLink())
}

func (p *Provider) checkConfigurationLink() (err error) {
	oidconfig := EndpointConfiguration{}
	resp, err := http.Get(p.ConfigurationLink)
	if err != nil {
		errors.Join(err, errors.New("error getting configuration link"))
	}
	if resp.StatusCode != 200 {
		return errors.Join(err, errors.New("got response code "+resp.Status))
	}
	err = json.NewDecoder(resp.Body).Decode(&oidconfig)
	if err != nil {
		return errors.Join(err, errors.New("error decoding configuration link"))
	}
	p.EndpointConfiguration = oidconfig
	return nil
}

func (p *Provider) checkLogoLink() (err error) {
	resp, err := http.Get(p.Logo)
	if err != nil {
		errors.Join(err, errors.New("error getting logo from link"))
	}
	if resp.StatusCode != 200 {
		return errors.Join(err, errors.New("got response code "+resp.Status))
	}
	return nil
}
