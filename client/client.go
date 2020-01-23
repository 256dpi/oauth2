// Package client implements a low-level OAuth2 client to perform the various
// request/response flows against a OAuth2 authentication server.
package client

import (
	"net/http"

	"github.com/256dpi/oauth2"
)

// Config is used to configure a client.
type Config struct {
	BaseURI               string
	TokenEndpoint         string
	IntrospectionEndpoint string
	RevocationEndpoint    string
	ResponseLimit         int64
}

// Default will return a default configuration.
func Default(baseURI string) Config {
	return Config{
		BaseURI:               baseURI,
		TokenEndpoint:         "/oauth2/token",
		IntrospectionEndpoint: "/oauth2/introspect",
		RevocationEndpoint:    "/oauth2/revoke",
	}
}

// Client is a low-level OAuth2 client.
type Client struct {
	config Config
	client *http.Client
}

// New will create and return a new client.
func New(config Config) *Client {
	return NewWithClient(config, new(http.Client))
}

// NewWithClient will create and return an new client using the provided client.
func NewWithClient(config Config, client *http.Client) *Client {
	// set default response limit
	if config.ResponseLimit == 0 {
		config.ResponseLimit = 2048
	}

	return &Client{
		config: config,
		client: client,
	}
}

// Authenticate will send the provided token request and return the servers
// token response or an error if failed.
func (c *Client) Authenticate(trq oauth2.TokenRequest) (*oauth2.TokenResponse, error) {
	// prepare endpoint
	endpoint := c.config.BaseURI + c.config.TokenEndpoint

	// build request
	req, err := oauth2.BuildTokenRequest(endpoint, trq)
	if err != nil {
		return nil, err
	}

	// perform request
	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	// ensure body is closed
	defer res.Body.Close()

	// check status
	if res.StatusCode != http.StatusOK {
		return nil, oauth2.ParseRequestError(res, c.config.ResponseLimit)
	}

	// parse response
	trs, err := oauth2.ParseTokenResponse(res, c.config.ResponseLimit)
	if err != nil {
		return nil, err
	}

	return trs, nil
}

// Introspect will send the provided introspection request and return the servers
// response of an error if failed.
func (c *Client) Introspect(irq oauth2.IntrospectionRequest) (*oauth2.IntrospectionResponse, error) {
	// prepare endpoint
	endpoint := c.config.BaseURI + c.config.IntrospectionEndpoint

	// build request
	req, err := oauth2.BuildIntrospectionRequest(endpoint, irq)
	if err != nil {
		return nil, err
	}

	// perform request
	res, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}

	// ensure body is closed
	defer res.Body.Close()

	// check status
	if res.StatusCode != http.StatusOK {
		return nil, oauth2.ParseRequestError(res, c.config.ResponseLimit)
	}

	// parse response
	irs, err := oauth2.ParseIntrospectionResponse(res, c.config.ResponseLimit)
	if err != nil {
		return nil, err
	}

	return irs, nil
}

// Revoke will send the provided revocation request and return and error if it
// failed.
func (c *Client) Revoke(rrq oauth2.RevocationRequest) error {
	// prepare endpoint
	endpoint := c.config.BaseURI + c.config.RevocationEndpoint

	// build request
	req, err := oauth2.BuildRevocationRequest(endpoint, rrq)
	if err != nil {
		return err
	}

	// perform request
	res, err := c.client.Do(req)
	if err != nil {
		return err
	}

	// ensure body is closed
	defer res.Body.Close()

	// check status
	if res.StatusCode != http.StatusOK {
		return oauth2.ParseRequestError(res, c.config.ResponseLimit)
	}

	return nil
}
