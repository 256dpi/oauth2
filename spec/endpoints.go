package spec

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TokenEndpointTest executes general token endpoint tests.
func TokenEndpointTest(t *testing.T, c *Config) {
	// invalid request
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.TokenEndpoint,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// unknown client
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: "unknown",
		Form: map[string]string{
			"grant_type": "password",
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_client", jsonFieldString(r, "error"), debug(r))
		},
	})

	// invalid grant type
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.TokenEndpoint,
		Form: map[string]string{
			"grant_type": "invalid",
		},
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
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
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// invalid client
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: map[string]string{
			"response_type": "code",
			"client_id":     "invalid",
			"redirect_uri":  c.PrimaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_client", jsonFieldString(r, "error"), debug(r))
			assert.NotEmpty(t, auth(r, "realm"), debug(r))
		},
	})

	// invalid redirect uri
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: map[string]string{
			"response_type": "code",
			"client_id":     c.ConfidentialClientID,
			"redirect_uri":  c.InvalidRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// invalid response type
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: map[string]string{
			"response_type": "invalid",
			"client_id":     c.ConfidentialClientID,
			"redirect_uri":  c.PrimaryRedirectURI,
		},
		Username: c.ConfidentialClientID,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// must respond to GET request
	Do(c.Handler, &Request{
		Method: "GET",
		Path:   c.AuthorizeEndpoint,
		Form: map[string]string{
			"response_type": "token",
			"client_id":     c.ConfidentialClientID,
			"redirect_uri":  c.PrimaryRedirectURI,
		},
		Username: c.ConfidentialClientID,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.NotEqual(t, http.StatusNotFound, r.Code, debug(r))
		},
	})
}

// RevocationEndpointTest executes general token revocation tests.
func RevocationEndpointTest(t *testing.T, c *Config) {
	// empty request
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.RevocationEndpoint,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// missing client
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.RevocationEndpoint,
		Form: map[string]string{
			"token": c.ValidToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// missing token
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.RevocationEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// invalid token type hint
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.RevocationEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Form: map[string]string{
			"token":           c.ValidToken,
			"token_type_hint": "invalid",
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "unsupported_token_type", jsonFieldString(r, "error"), debug(r))
		},
	})

	// unknown client
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.RevocationEndpoint,
		Form: map[string]string{
			"token": c.ValidToken,
		},
		Username: "unknown",
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_client", jsonFieldString(r, "error"), debug(r))
			assert.NotEmpty(t, auth(r, "realm"), debug(r))
		},
	})

	// unauthenticated client
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.RevocationEndpoint,
		Form: map[string]string{
			"token": c.ValidToken,
		},
		Username: c.ConfidentialClientID,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_client", jsonFieldString(r, "error"), debug(r))
			assert.NotEmpty(t, auth(r, "realm"), debug(r))
		},
	})

	// wrong client
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.RevocationEndpoint,
		Form: map[string]string{
			"token": c.ValidToken,
		},
		Username: c.PublicClientID,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_client", jsonFieldString(r, "error"), debug(r))
		},
	})

	// invalid token
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.RevocationEndpoint,
		Form: map[string]string{
			"token": c.InvalidToken,
		},
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusOK, r.Code, debug(r))
		},
	})

	// unknown token
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.RevocationEndpoint,
		Form: map[string]string{
			"token": c.UnknownToken,
		},
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusOK, r.Code, debug(r))
		},
	})

	// test existence and revocation
	AccessTokenTest(t, c, c.ValidToken)

	// revocation of refresh tokens is tested by RefreshTokenGrantTest
}

// IntrospectionEndpointTest executes general token introspection tests.
func IntrospectionEndpointTest(t *testing.T, c *Config) {
	// wrong method
	Do(c.Handler, &Request{
		Method: "GET",
		Path:   c.IntrospectionEndpoint,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// empty request
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.IntrospectionEndpoint,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// missing client
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.IntrospectionEndpoint,
		Form: map[string]string{
			"token": c.ValidToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// missing token
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.IntrospectionEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// invalid token type hint
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.IntrospectionEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Form: map[string]string{
			"token":           c.ValidToken,
			"token_type_hint": "invalid",
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "unsupported_token_type", jsonFieldString(r, "error"), debug(r))
		},
	})

	// unknown client
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.IntrospectionEndpoint,
		Form: map[string]string{
			"token": c.ValidToken,
		},
		Username: "unknown",
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_client", jsonFieldString(r, "error"), debug(r))
			assert.NotEmpty(t, auth(r, "realm"), debug(r))
		},
	})

	// unauthenticated client
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.IntrospectionEndpoint,
		Form: map[string]string{
			"token": c.ValidToken,
		},
		Username: c.ConfidentialClientID,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_client", jsonFieldString(r, "error"), debug(r))
			assert.NotEmpty(t, auth(r, "realm"), debug(r))
		},
	})

	// wrong client
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.IntrospectionEndpoint,
		Form: map[string]string{
			"token": c.ValidToken,
		},
		Username: c.PublicClientID,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_client", jsonFieldString(r, "error"), debug(r))
		},
	})

	// invalid token
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.IntrospectionEndpoint,
		Form: map[string]string{
			"token": c.InvalidToken,
		},
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// unknown token
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.IntrospectionEndpoint,
		Form: map[string]string{
			"token": c.UnknownToken,
		},
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusOK, r.Code, debug(r))
		},
	})

	// valid access token
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.IntrospectionEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Form: map[string]string{
			"token":           c.ValidToken,
			"token_type_hint": "access_token",
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusOK, r.Code, debug(r))
			assert.True(t, jsonFieldBool(r, "active"), debug(r))
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
			assert.NotEmpty(t, auth(r, "realm"), debug(r))
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
			assert.Equal(t, "invalid_request", auth(r, "error"), debug(r))
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
			assert.Equal(t, "invalid_token", auth(r, "error"), debug(r))
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
			assert.Equal(t, "invalid_token", auth(r, "error"), debug(r))
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
			assert.Equal(t, "invalid_token", auth(r, "error"), debug(r))
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
			assert.Equal(t, "insufficient_scope", auth(r, "error"), debug(r))
			assert.Empty(t, r.Body.String(), debug(r))
		},
	})
}
