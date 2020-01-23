package oauth2test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TokenEndpointTest executes general token endpoint tests.
func TokenEndpointTest(t *testing.T, spec *Spec) {
	// invalid request
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.TokenEndpoint,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// unknown client
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
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
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.TokenEndpoint,
		Form: map[string]string{
			"grant_type": "invalid",
		},
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})
}

// AuthorizationEndpointTest executes general authorization endpoint tests.
func AuthorizationEndpointTest(t *testing.T, spec *Spec) {
	// invalid request
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.AuthorizeEndpoint,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// invalid client
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.AuthorizeEndpoint,
		Form: map[string]string{
			"response_type": "code",
			"client_id":     "invalid",
			"redirect_uri":  spec.PrimaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_client", jsonFieldString(r, "error"), debug(r))
			assert.NotEmpty(t, auth(r, "realm"), debug(r))
		},
	})

	// invalid redirect uri
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.AuthorizeEndpoint,
		Form: map[string]string{
			"response_type": "code",
			"client_id":     spec.ConfidentialClientID,
			"redirect_uri":  spec.InvalidRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// invalid response type
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.AuthorizeEndpoint,
		Form: map[string]string{
			"response_type": "invalid",
			"client_id":     spec.ConfidentialClientID,
			"redirect_uri":  spec.PrimaryRedirectURI,
		},
		Username: spec.ConfidentialClientID,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// must respond to GET request
	Do(spec.Handler, &Request{
		Method: "GET",
		Path:   spec.AuthorizeEndpoint,
		Form: map[string]string{
			"response_type": "token",
			"client_id":     spec.ConfidentialClientID,
			"redirect_uri":  spec.PrimaryRedirectURI,
		},
		Username: spec.ConfidentialClientID,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.NotEqual(t, http.StatusNotFound, r.Code, debug(r))
		},
	})
}

// RevocationEndpointTest executes general token revocation tests.
func RevocationEndpointTest(t *testing.T, spec *Spec) {
	// empty request
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.RevocationEndpoint,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// missing client
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.RevocationEndpoint,
		Form: map[string]string{
			"token": spec.ValidToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// missing token
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.RevocationEndpoint,
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// invalid token type hint
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.RevocationEndpoint,
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Form: map[string]string{
			"token":           spec.ValidToken,
			"token_type_hint": "invalid",
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "unsupported_token_type", jsonFieldString(r, "error"), debug(r))
		},
	})

	// unknown client
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.RevocationEndpoint,
		Form: map[string]string{
			"token": spec.ValidToken,
		},
		Username: "unknown",
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_client", jsonFieldString(r, "error"), debug(r))
			assert.NotEmpty(t, auth(r, "realm"), debug(r))
		},
	})

	// unauthenticated client
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.RevocationEndpoint,
		Form: map[string]string{
			"token": spec.ValidToken,
		},
		Username: spec.ConfidentialClientID,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_client", jsonFieldString(r, "error"), debug(r))
			assert.NotEmpty(t, auth(r, "realm"), debug(r))
		},
	})

	// wrong client
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.RevocationEndpoint,
		Form: map[string]string{
			"token": spec.ValidToken,
		},
		Username: spec.PublicClientID,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_client", jsonFieldString(r, "error"), debug(r))
		},
	})

	// invalid token
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.RevocationEndpoint,
		Form: map[string]string{
			"token": spec.InvalidToken,
		},
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// unknown token
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.RevocationEndpoint,
		Form: map[string]string{
			"token": spec.UnknownToken,
		},
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusOK, r.Code, debug(r))
		},
	})

	// test existence and revocation
	AccessTokenTest(t, spec, spec.ValidToken)

	// revocation of refresh tokens is tested by RefreshTokenGrantTest
}

// IntrospectionEndpointTest executes general token introspection tests.
func IntrospectionEndpointTest(t *testing.T, spec *Spec) {
	// wrong method
	Do(spec.Handler, &Request{
		Method: "GET",
		Path:   spec.IntrospectionEndpoint,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// empty request
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.IntrospectionEndpoint,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// missing client
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.IntrospectionEndpoint,
		Form: map[string]string{
			"token": spec.ValidToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// missing token
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.IntrospectionEndpoint,
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// invalid token type hint
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.IntrospectionEndpoint,
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Form: map[string]string{
			"token":           spec.ValidToken,
			"token_type_hint": "invalid",
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "unsupported_token_type", jsonFieldString(r, "error"), debug(r))
		},
	})

	// unknown client
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.IntrospectionEndpoint,
		Form: map[string]string{
			"token": spec.ValidToken,
		},
		Username: "unknown",
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_client", jsonFieldString(r, "error"), debug(r))
			assert.NotEmpty(t, auth(r, "realm"), debug(r))
		},
	})

	// unauthenticated client
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.IntrospectionEndpoint,
		Form: map[string]string{
			"token": spec.ValidToken,
		},
		Username: spec.ConfidentialClientID,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_client", jsonFieldString(r, "error"), debug(r))
			assert.NotEmpty(t, auth(r, "realm"), debug(r))
		},
	})

	// wrong client
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.IntrospectionEndpoint,
		Form: map[string]string{
			"token": spec.ValidToken,
		},
		Username: spec.PublicClientID,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_client", jsonFieldString(r, "error"), debug(r))
		},
	})

	// invalid token
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.IntrospectionEndpoint,
		Form: map[string]string{
			"token": spec.InvalidToken,
		},
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// unknown token
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.IntrospectionEndpoint,
		Form: map[string]string{
			"token": spec.UnknownToken,
		},
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusOK, r.Code, debug(r))
		},
	})

	// valid access token
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.IntrospectionEndpoint,
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Form: map[string]string{
			"token":           spec.ValidToken,
			"token_type_hint": "access_token",
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusOK, r.Code, debug(r))
			assert.True(t, jsonFieldBool(r, "active"), debug(r))
		},
	})
}

// ProtectedResourceTest validates authorization of the protected resource.
func ProtectedResourceTest(t *testing.T, spec *Spec) {
	// missing token
	Do(spec.Handler, &Request{
		Method: "GET",
		Path:   spec.ProtectedResource,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.NotEmpty(t, auth(r, "realm"), debug(r))
			assert.Empty(t, r.Body.String(), debug(r))
		},
	})

	// invalid header
	Do(spec.Handler, &Request{
		Method: "GET",
		Path:   spec.ProtectedResource,
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
	Do(spec.Handler, &Request{
		Method: "GET",
		Path:   spec.ProtectedResource,
		Header: map[string]string{
			"Authorization": "Bearer " + spec.InvalidToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_token", auth(r, "error"), debug(r))
			assert.Empty(t, r.Body.String(), debug(r))
		},
	})

	// unknown token
	Do(spec.Handler, &Request{
		Method: "GET",
		Path:   spec.ProtectedResource,
		Header: map[string]string{
			"Authorization": "Bearer " + spec.UnknownToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_token", auth(r, "error"), debug(r))
			assert.Empty(t, r.Body.String(), debug(r))
		},
	})

	// expired token
	Do(spec.Handler, &Request{
		Method: "GET",
		Path:   spec.ProtectedResource,
		Header: map[string]string{
			"Authorization": "Bearer " + spec.ExpiredToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_token", auth(r, "error"), debug(r))
			assert.Empty(t, r.Body.String(), debug(r))
		},
	})

	// insufficient token
	Do(spec.Handler, &Request{
		Method: "GET",
		Path:   spec.ProtectedResource,
		Header: map[string]string{
			"Authorization": "Bearer " + spec.InsufficientToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusForbidden, r.Code, debug(r))
			assert.Equal(t, "insufficient_scope", auth(r, "error"), debug(r))
			assert.Empty(t, r.Body.String(), debug(r))
		},
	})
}
