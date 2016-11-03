package spec

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TokenEndpointTest executes general token endpoint tests.
func TokenEndpointTest(t *testing.T, c *Config) {
	// invalid request
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.TokenEndpoint,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			if r.Code != http.StatusBadRequest {
				t.Error("expected status bad request", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_request" {
				t.Error(`expected error to be "invalid_request"`, debug(r))
			}
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
			if r.Code != http.StatusUnauthorized {
				t.Error("expected status unauthorized", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_client" {
				t.Error(`expected error to be "invalid_client"`, debug(r))
			}
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
			if r.Code != http.StatusBadRequest {
				t.Error("expected status bad request", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_request" {
				t.Error(`expected error to be "invalid_request"`, debug(r))
			}
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
			if r.Code != http.StatusBadRequest {
				t.Error("expected status bad request", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_request" {
				t.Error(`expected error to be "invalid_request"`, debug(r))
			}
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
			if r.Code != http.StatusUnauthorized {
				t.Error("expected status unauthorized", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_client" {
				t.Error(`expected error to be "invalid_client"`, debug(r))
			}

			if !strings.HasPrefix(r.HeaderMap.Get("WWW-Authenticate"), "Basic realm=") {
				t.Error(`expected header WWW-Authenticate to include a realm"`, debug(r))
			}
		},
	})

	// invalid redirect uri
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: map[string]string{
			"response_type": "code",
			"client_id":     c.PrimaryClientID,
			"redirect_uri":  c.InvalidRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			if r.Code != http.StatusBadRequest {
				t.Error("expected status bad request", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_request" {
				t.Error(`expected error to be "invalid_request"`, debug(r))
			}
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
			if r.Code != http.StatusBadRequest {
				t.Error("expected status bad request", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_request" {
				t.Error(`expected error to be "invalid_request"`, debug(r))
			}
		},
	})

	// must respond to GET request
	Do(c.Handler, &Request{
		Method: "GET",
		Path:   c.AuthorizeEndpoint,
		Form: map[string]string{
			"response_type": "token",
			"client_id":     c.PrimaryClientID,
			"redirect_uri":  c.PrimaryRedirectURI,
		},
		Username: c.PrimaryClientID,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			if r.Code == http.StatusNotFound {
				t.Error("expected different status than not found", debug(r))
			}
		},
	})
}

// RevocationEndpointTest executes general token revocation tests.
func RevocationEndpointTest(t *testing.T, c *Config) {
	// invalid request
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.RevocationEndpoint,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			if r.Code != http.StatusBadRequest {
				t.Error("expected status bad request", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_request" {
				t.Error(`expected error to be "invalid_request"`, debug(r))
			}
		},
	})

	// invalid client
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.RevocationEndpoint,
		Form: map[string]string{
			"token": c.ValidRefreshToken,
		},
		Username: "invalid",
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			if r.Code != http.StatusUnauthorized {
				t.Error("expected status unauthorized", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_client" {
				t.Error(`expected error to be "invalid_client"`, debug(r))
			}

			if !strings.HasPrefix(r.HeaderMap.Get("WWW-Authenticate"), "Basic realm=") {
				t.Error(`expected header WWW-Authenticate to include a realm"`, debug(r))
			}
		},
	})

	// invalid token
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.RevocationEndpoint,
		Form: map[string]string{
			"token": c.InvalidToken,
		},
		Username: c.PrimaryClientID,
		Password: c.PrimaryClientSecret,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			if r.Code != http.StatusOK {
				t.Error("expected status bad request", debug(r))
			}
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
			if r.Code != http.StatusUnauthorized {
				t.Error("expected status unauthorized", debug(r))
			}

			if !strings.HasPrefix(r.HeaderMap.Get("WWW-Authenticate"), `Bearer realm=`) {
				t.Error(`expected header WWW-Authenticate to include a realm`, debug(r))
			}

			if r.Body.String() != "" {
				t.Error("expected empty body", debug(r))
			}
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
			if r.Code != http.StatusBadRequest {
				t.Error("expected status bad request", debug(r))
			}

			if !strings.HasPrefix(r.HeaderMap.Get("WWW-Authenticate"), `Bearer error="invalid_request"`) {
				t.Error(`expected header WWW-Authenticate to include the error "invalid_request"`, debug(r))
			}

			if r.Body.String() != "" {
				t.Error("expected empty body", debug(r))
			}
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
			if r.Code != http.StatusUnauthorized {
				t.Error("expected status unauthorized", debug(r))
			}

			if !strings.HasPrefix(r.HeaderMap.Get("WWW-Authenticate"), `Bearer error="invalid_token"`) {
				t.Error(`expected header WWW-Authenticate to include the error "invalid_token"`, debug(r))
			}

			if r.Body.String() != "" {
				t.Error("expected empty body", debug(r))
			}
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
			if r.Code != http.StatusUnauthorized {
				t.Error("expected status unauthorized", debug(r))
			}

			if !strings.HasPrefix(r.HeaderMap.Get("WWW-Authenticate"), `Bearer error="invalid_token"`) {
				t.Error(`expected header WWW-Authenticate to include the error "invalid_token"`, debug(r))
			}

			if r.Body.String() != "" {
				t.Error("expected empty body", debug(r))
			}
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
			if r.Code != http.StatusUnauthorized {
				t.Error("expected status unauthorized", debug(r))
			}

			if !strings.HasPrefix(r.HeaderMap.Get("WWW-Authenticate"), `Bearer error="invalid_token"`) {
				t.Error(`expected header WWW-Authenticate to include the error "invalid_token"`, debug(r))
			}

			if r.Body.String() != "" {
				t.Error("expected empty body", debug(r))
			}
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
			if r.Code != http.StatusForbidden {
				t.Error("expected status forbidden", debug(r))
			}

			if !strings.HasPrefix(r.HeaderMap.Get("WWW-Authenticate"), `Bearer error="insufficient_scope"`) {
				t.Error(`expected header WWW-Authenticate to include the error "insufficient_scope"`, debug(r))
			}

			if r.Body.String() != "" {
				t.Error("expected empty body", debug(r))
			}
		},
	})
}
