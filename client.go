package oauth2

import (
	"net/http"
)

// ClientConfig is used to configure a client.
type ClientConfig struct {
	BaseURI               string
	TokenEndpoint         string
	IntrospectionEndpoint string
	RevocationEndpoint    string
	ResponseLimit         int64
}

// Default will return a default configuration.
func Default(baseURI string) ClientConfig {
	return ClientConfig{
		BaseURI:               baseURI,
		TokenEndpoint:         "/oauth2/token",
		IntrospectionEndpoint: "/oauth2/introspect",
		RevocationEndpoint:    "/oauth2/revoke",
	}
}

// Client is a low-level OAuth2 client.
type Client struct {
	config ClientConfig
	client *http.Client
}

// NewClient will create and return a new client.
func NewClient(config ClientConfig) *Client {
	return NewClientWithClient(config, new(http.Client))
}

// NewClientWithClient will create and return an new client using the provided
// client.
func NewClientWithClient(config ClientConfig, client *http.Client) *Client {
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
func (c *Client) Authenticate(trq TokenRequest) (*TokenResponse, error) {
	// prepare endpoint
	endpoint := c.config.BaseURI + c.config.TokenEndpoint

	// build request
	req, err := BuildTokenRequest(endpoint, trq)
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
		return nil, ParseRequestError(res, c.config.ResponseLimit)
	}

	// parse response
	trs, err := ParseTokenResponse(res, c.config.ResponseLimit)
	if err != nil {
		return nil, err
	}

	return trs, nil
}

// Introspect will send the provided introspection request and return the servers
// response of an error if failed.
func (c *Client) Introspect(irq IntrospectionRequest) (*IntrospectionResponse, error) {
	// prepare endpoint
	endpoint := c.config.BaseURI + c.config.IntrospectionEndpoint

	// build request
	req, err := BuildIntrospectionRequest(endpoint, irq)
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
		return nil, ParseRequestError(res, c.config.ResponseLimit)
	}

	// parse response
	irs, err := ParseIntrospectionResponse(res, c.config.ResponseLimit)
	if err != nil {
		return nil, err
	}

	return irs, nil
}

// Revoke will send the provided revocation request and return and error if it
// failed.
func (c *Client) Revoke(rrq RevocationRequest) error {
	// prepare endpoint
	endpoint := c.config.BaseURI + c.config.RevocationEndpoint

	// build request
	req, err := BuildRevocationRequest(endpoint, rrq)
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
		return ParseRequestError(res, c.config.ResponseLimit)
	}

	return nil
}
