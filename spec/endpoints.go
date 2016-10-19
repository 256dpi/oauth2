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
		Username: c.PrimaryClientID,
		Password: c.PrimaryClientSecret,
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
			"redirect_uri":  c.PrimaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
			assert.Equal(t, "invalid_client", gjson.Get(r.Body.String(), "error").Str)
			assert.Contains(t, r.HeaderMap.Get("WWW-Authenticate"), `Basic realm=`)
		},
	})

	// invalid redirect uri
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: map[string]string{
			"response_type": oauth2.CodeResponseType,
			"client_id":     c.PrimaryClientID,
			"redirect_uri":  c.InvalidRedirectURI,
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
			"client_id":     c.PrimaryClientID,
			"redirect_uri":  c.PrimaryRedirectURI,
		},
		Username: c.PrimaryClientID,
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
			"client_id":     c.PrimaryClientID,
			"redirect_uri":  c.PrimaryRedirectURI,
		},
		Username: c.PrimaryClientID,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusOK, r.Code)
			assert.NotEmpty(t, r.Body.String())
		},
	})
}

// ProtectedResourceTest validates authorization of the protected resource.
func ProtectedResourceTest(t *testing.T, c *Config) {
	// missing token
	Do(c.Handler, &Request{
		Method: "GET",
		Path:   c.ProtectedResource,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
			assert.Contains(t, r.HeaderMap.Get("WWW-Authenticate"), `Bearer realm=`)
			assert.Empty(t, r.Body.String())
		},
	})

	// invalid header
	Do(c.Handler, &Request{
		Method: "GET",
		Path:   c.ProtectedResource,
		Header: map[string]string{
			"Authorization": "invalid",
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Contains(t, r.HeaderMap.Get("WWW-Authenticate"), `Bearer error="invalid_request"`)
			assert.Empty(t, r.Body.String())
		},
	})

	// invalid token
	Do(c.Handler, &Request{
		Method: "GET",
		Path:   c.ProtectedResource,
		Header: map[string]string{
			"Authorization": "Bearer " + c.InvalidToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
			assert.Contains(t, r.HeaderMap.Get("WWW-Authenticate"), `Bearer error="invalid_token"`)
			assert.Empty(t, r.Body.String())
		},
	})

	// unknown token
	Do(c.Handler, &Request{
		Method: "GET",
		Path:   c.ProtectedResource,
		Header: map[string]string{
			"Authorization": "Bearer " + c.UnknownToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
			assert.Contains(t, r.HeaderMap.Get("WWW-Authenticate"), `Bearer error="invalid_token"`)
			assert.Empty(t, r.Body.String())
		},
	})

	// expired token
	Do(c.Handler, &Request{
		Method: "GET",
		Path:   c.ProtectedResource,
		Header: map[string]string{
			"Authorization": "Bearer " + c.ExpiredToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
			assert.Contains(t, r.HeaderMap.Get("WWW-Authenticate"), `Bearer error="invalid_token"`)
			assert.Empty(t, r.Body.String())
		},
	})

	// insufficient token
	Do(c.Handler, &Request{
		Method: "GET",
		Path:   c.ProtectedResource,
		Header: map[string]string{
			"Authorization": "Bearer " + c.InsufficientToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusForbidden, r.Code)
			assert.Contains(t, r.HeaderMap.Get("WWW-Authenticate"), `Bearer error="insufficient_scope"`)
			assert.Empty(t, r.Body.String())
		},
	})
}
