package spec

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// AccessTokenTest validates the specified access token by requesting the
// protected resource.
func AccessTokenTest(t *testing.T, c *Config, accessToken string) {
	// test authorization
	Do(c.Handler, &Request{
		Method: "GET",
		Path:   c.ProtectedResource,
		Header: map[string]string{
			"Authorization": "Bearer " + accessToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			if r.Code != http.StatusOK {
				t.Error("expected status ok", debug(r))
			}
		},
	})

	// check if revocation is available
	if c.RevocationEndpoint == "" {
		return
	}

	// revoke access token
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.RevocationEndpoint,
		Form: map[string]string{
			"token":           accessToken,
			"token_type_hint": "access_token",
		},
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			if r.Code != http.StatusOK {
				t.Error("expected status ok", debug(r))
			}
		},
	})

	// check token
	Do(c.Handler, &Request{
		Method: "GET",
		Path:   c.ProtectedResource,
		Header: map[string]string{
			"Authorization": "Bearer " + accessToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			if r.Code != http.StatusUnauthorized {
				t.Error("expected status unauthorized", debug(r))
			}
		},
	})
}

// RefreshTokenTest validates the specified refreshToken by requesting a new
// access token and validating it as well.
func RefreshTokenTest(t *testing.T, c *Config, refreshToken string) {
	var accessToken, newRefreshToken string

	// test refresh token grant
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": refreshToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			if r.Code != http.StatusOK {
				t.Error("expected status ok", debug(r))
			}

			if jsonFieldString(r, "token_type") != "bearer" {
				t.Error(`expected token_type to be "bearer"`, debug(r))
			}

			if jsonFieldString(r, "scope") != c.ValidScope {
				t.Error(`expected scope to be the valid scope`, debug(r))
			}

			if jsonFieldFloat(r, "expires_in") != float64(c.ExpectedExpiresIn) {
				t.Error(`expected expires_in to be the expected expires in`, debug(r))
			}

			accessToken = jsonFieldString(r, "access_token")

			if accessToken == "" {
				t.Error(`expected access_token to be present`, debug(r))
			}

			newRefreshToken = jsonFieldString(r, "refresh_token")
		},
	})

	// test access token
	AccessTokenTest(t, c, accessToken)

	// check if revocation is available
	if c.RevocationEndpoint == "" {
		return
	}

	// revoke refresh token
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.RevocationEndpoint,
		Form: map[string]string{
			"token":           newRefreshToken,
			"token_type_hint": "refresh_token",
		},
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			if r.Code != http.StatusOK {
				t.Error("expected status ok", debug(r))
			}
		},
	})

	// check token
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": newRefreshToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			if r.Code != http.StatusBadRequest {
				t.Error("expected status bad request", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_grant" {
				t.Error(`expected error to be "invalid_grant"`, debug(r))
			}
		},
	})
}
