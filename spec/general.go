package spec

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

// AccessTokenTest validates the specified access token by requesting the
// protected resource.
func AccessTokenTest(t *testing.T, c *Config, accessToken string) {
	// check token functionality
	Do(c.Handler, &Request{
		Method: "GET",
		Path:   c.ProtectedResource,
		Header: map[string]string{
			"Authorization": "Bearer " + accessToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusOK, r.Code, debug(r))
		},
	})

	// check if access token is active
	if c.IntrospectionEndpoint != "" {
		Do(c.Handler, &Request{
			Method:   "POST",
			Path:     c.IntrospectionEndpoint,
			Username: c.ConfidentialClientID,
			Password: c.ConfidentialClientSecret,
			Form: map[string]string{
				"token":           accessToken,
				"token_type_hint": "access_token",
			},
			Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
				assert.Equal(t, http.StatusOK, r.Code, debug(r))
				assert.True(t, jsonFieldBool(r, "active"), debug(r))
				assert.Equal(t, "access_token", jsonFieldString(r, "token_type"), debug(r))
			},
		})
	}

	// skip if revocation is not available
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
			assert.Equal(t, http.StatusOK, r.Code, debug(r))
		},
	})

	// check token functionality
	Do(c.Handler, &Request{
		Method: "GET",
		Path:   c.ProtectedResource,
		Header: map[string]string{
			"Authorization": "Bearer " + accessToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_token", auth(r, "error"), debug(r))
		},
	})

	// check if access token is now inactive
	if c.IntrospectionEndpoint != "" {
		Do(c.Handler, &Request{
			Method:   "POST",
			Path:     c.IntrospectionEndpoint,
			Username: c.ConfidentialClientID,
			Password: c.ConfidentialClientSecret,
			Form: map[string]string{
				"token":           accessToken,
				"token_type_hint": "access_token",
			},
			Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
				assert.Equal(t, http.StatusOK, r.Code, debug(r))
				assert.False(t, jsonFieldBool(r, "active"), debug(r))
			},
		})
	}
}

// RefreshTokenTest validates the specified refreshToken by requesting a new
// access token and validating it as well.
func RefreshTokenTest(t *testing.T, c *Config, refreshToken string) {
	// check if refresh token is active
	if c.IntrospectionEndpoint != "" {
		Do(c.Handler, &Request{
			Method:   "POST",
			Path:     c.IntrospectionEndpoint,
			Username: c.ConfidentialClientID,
			Password: c.ConfidentialClientSecret,
			Form: map[string]string{
				"token":           refreshToken,
				"token_type_hint": "refresh_token",
			},
			Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
				assert.Equal(t, http.StatusOK, r.Code, debug(r))
				assert.True(t, jsonFieldBool(r, "active"), debug(r))
				assert.Equal(t, "refresh_token", jsonFieldString(r, "token_type"), debug(r))
			},
		})
	}

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
			assert.Equal(t, http.StatusOK, r.Code, debug(r))
			assert.Equal(t, "bearer", jsonFieldString(r, "token_type"), debug(r))
			assert.Equal(t, c.ValidScope, jsonFieldString(r, "scope"), debug(r))
			assert.Equal(t, float64(c.ExpectedExpiresIn), jsonFieldFloat(r, "expires_in"), debug(r))

			accessToken = jsonFieldString(r, "access_token")
			assert.NotEmpty(t, accessToken, debug(r))

			newRefreshToken = jsonFieldString(r, "refresh_token")
			assert.NotEmpty(t, newRefreshToken, debug(r))
		},
	})

	// test access token
	AccessTokenTest(t, c, accessToken)

	// check if refresh token is spent
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
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_grant", jsonFieldString(r, "error"), debug(r))
		},
	})

	// check if refresh token is now inactive
	if c.IntrospectionEndpoint != "" {
		Do(c.Handler, &Request{
			Method:   "POST",
			Path:     c.IntrospectionEndpoint,
			Username: c.ConfidentialClientID,
			Password: c.ConfidentialClientSecret,
			Form: map[string]string{
				"token":           refreshToken,
				"token_type_hint": "refresh_token",
			},
			Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
				assert.Equal(t, http.StatusOK, r.Code, debug(r))
				assert.False(t, jsonFieldBool(r, "active"), debug(r))
			},
		})
	}

	// skip if revocation is not available
	if c.RevocationEndpoint == "" {
		return
	}

	// revoke new refresh token
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
			assert.Equal(t, http.StatusOK, r.Code, debug(r))
		},
	})

	// check if new refresh token is revoked
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
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_grant", jsonFieldString(r, "error"), debug(r))
		},
	})

	// check if new refresh token is now inactive
	if c.IntrospectionEndpoint != "" {
		Do(c.Handler, &Request{
			Method:   "POST",
			Path:     c.IntrospectionEndpoint,
			Username: c.ConfidentialClientID,
			Password: c.ConfidentialClientSecret,
			Form: map[string]string{
				"token":           newRefreshToken,
				"token_type_hint": "refresh_token",
			},
			Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
				assert.Equal(t, http.StatusOK, r.Code, debug(r))
				assert.False(t, jsonFieldBool(r, "active"), debug(r))
			},
		})
	}
}
