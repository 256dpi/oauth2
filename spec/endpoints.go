package spec

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gonfire/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/tidwall/gjson"
)

// TokenEndpointTest executes general token endpoint tests.
func TokenEndpointTest(t *testing.T, c *Config) {
	// invalid request
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.TokenEndpoint,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_request", gjson.Get(r.Body.String(), "error").Str)
		},
	})

	// invalid grant type
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.TokenEndpoint,
		Form: map[string]string{
			"grant_type": "invalid",
		},
		Username: c.ClientID,
		Password: c.ClientSecret,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_request", gjson.Get(r.Body.String(), "error").Str)
		},
	})
}

// AuthorizationEndpointTest executes general authorization endpoint tests.
func AuthorizationEndpointTest(t *testing.T, c *Config) {
	// invalid request
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_request", gjson.Get(r.Body.String(), "error").Str)
		},
	})

	// invalid client
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: map[string]string{
			"response_type": oauth2.CodeResponseType,
			"client_id":     "invalid",
			"redirect_uri":  c.ValidRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
			assert.Equal(t, "invalid_client", gjson.Get(r.Body.String(), "error").Str)
			assert.Equal(t, `Basic realm="OAuth2"`, r.HeaderMap.Get("WWW-Authenticate"))
		},
	})

	// invalid redirect uri
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: map[string]string{
			"response_type": oauth2.CodeResponseType,
			"client_id":     c.ClientID,
			"redirect_uri":  "http://inval.id",
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_request", gjson.Get(r.Body.String(), "error").Str)
		},
	})

	// invalid response type
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: map[string]string{
			"response_type": "invalid",
			"client_id":     c.ClientID,
			"redirect_uri":  c.ValidRedirectURI,
		},
		Username: c.ClientID,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_request", gjson.Get(r.Body.String(), "error").Str)
		},
	})

	// must respond to GET request
	Do(c.Handler, &Request{
		Method: "GET",
		Path:   c.AuthorizeEndpoint,
		Form: map[string]string{
			"response_type": oauth2.TokenResponseType,
			"client_id":     c.ClientID,
			"redirect_uri":  c.ValidRedirectURI,
		},
		Username: c.ClientID,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusOK, r.Code)
			assert.NotEmpty(t, r.Body.String())
		},
	})
}
