package spec

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gonfire/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/tidwall/gjson"
)

// AccessTokenTest validates the specified access token by requesting the
// protected resource.
func AccessTokenTest(t *testing.T, c *Config, accessToken string) {
	Do(c.Handler, &Request{
		Method: "GET",
		Path:   c.ProtectedResource,
		Header: map[string]string{
			"Authorization": "Bearer " + accessToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusOK, r.Code)
			assert.NotEmpty(t, r.Body.String())
		},
	})
}

// RefreshTokenTest validates the specified refreshToken by requesting a new
// access token and validating it as well.
func RefreshTokenTest(t *testing.T, c *Config, refreshToken string) {
	var accessToken string

	// test refresh token grant
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.PrimaryClientID,
		Password: c.PrimaryClientSecret,
		Form: map[string]string{
			"grant_type":    oauth2.RefreshTokenGrantType,
			"refresh_token": refreshToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusOK, r.Code)
			assert.Equal(t, "bearer", gjson.Get(r.Body.String(), "token_type").String())
			assert.Equal(t, int64(c.ExpectedExpireIn), gjson.Get(r.Body.String(), "expires_in").Int())

			accessToken = gjson.Get(r.Body.String(), "access_token").String()
			assert.NotEmpty(t, accessToken)
		},
	})

	// test access token
	AccessTokenTest(t, c, accessToken)

	// test refresh token invalidation
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.PrimaryClientID,
		Password: c.PrimaryClientSecret,
		Form: map[string]string{
			"grant_type":    oauth2.RefreshTokenGrantType,
			"refresh_token": refreshToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_grant", gjson.Get(r.Body.String(), "error").String())
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
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Contains(t, r.HeaderMap.Get("WWW-Authenticate"), `Bearer error="invalid_request"`)
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
