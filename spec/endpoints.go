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
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", gjson.Get(r.Body.String(), "error").Str, debug(r))
		},
	})

	// unknown client
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: "unknown",
		Form: map[string]string{
			"grant_type": oauth2.PasswordGrantType,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_client", gjson.Get(r.Body.String(), "error").Str, debug(r))
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
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", gjson.Get(r.Body.String(), "error").Str, debug(r))
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
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", gjson.Get(r.Body.String(), "error").Str, debug(r))
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
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_client", gjson.Get(r.Body.String(), "error").Str, debug(r))
			assert.Contains(t, r.HeaderMap.Get("WWW-Authenticate"), `Basic realm=`, debug(r))
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
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", gjson.Get(r.Body.String(), "error").Str, debug(r))
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
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", gjson.Get(r.Body.String(), "error").Str, debug(r))
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
			assert.NotEqual(t, http.StatusNotFound, r.Code, debug(r))
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
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Contains(t, r.HeaderMap.Get("WWW-Authenticate"), `Bearer realm=`, debug(r))
			assert.Empty(t, r.Body.String(), debug(r))
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
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Contains(t, r.HeaderMap.Get("WWW-Authenticate"), `Bearer error="invalid_request"`, debug(r))
			assert.Empty(t, r.Body.String(), debug(r))
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
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Contains(t, r.HeaderMap.Get("WWW-Authenticate"), `Bearer error="invalid_token"`, debug(r))
			assert.Empty(t, r.Body.String(), debug(r))
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
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Contains(t, r.HeaderMap.Get("WWW-Authenticate"), `Bearer error="invalid_token"`, debug(r))
			assert.Empty(t, r.Body.String(), debug(r))
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
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Contains(t, r.HeaderMap.Get("WWW-Authenticate"), `Bearer error="invalid_token"`, debug(r))
			assert.Empty(t, r.Body.String(), debug(r))
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
			assert.Equal(t, http.StatusForbidden, r.Code, debug(r))
			assert.Contains(t, r.HeaderMap.Get("WWW-Authenticate"), `Bearer error="insufficient_scope"`, debug(r))
			assert.Empty(t, r.Body.String(), debug(r))
		},
	})
}
