package spec

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tidwall/gjson"
)

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

func RefreshTokenTest(t *testing.T, c *Config, refreshToken string) {
	var accessToken string

	// test refresh token flow
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ClientID,
		Password: c.ClientSecret,
		Form: map[string]string{
			"grant_type":    "refresh_token",
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
		Username: c.ClientID,
		Password: c.ClientSecret,
		Form: map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": refreshToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_grant", gjson.Get(r.Body.String(), "error").String())
		},
	})
}

func UnauthorizedAccessTest(t *testing.T, c *Config) {
	Do(c.Handler, &Request{
		Method: "GET",
		Path:   c.ProtectedResource,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
			assert.Equal(t, "", r.Body.String())
		},
	})
}

func UnsupportedGrantTypeTest(t *testing.T, c *Config) {
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.TokenEndpoint,
		Form: map[string]string{
			"grant_type": "foo",
		},
		Username: c.ClientID,
		Password: c.ClientSecret,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "unsupported_grant_type", gjson.Get(r.Body.String(), "error").Str)
		},
	})
}

func UnsupportedResponseTypeTest(t *testing.T, c *Config) {
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: map[string]string{
			"response_type": "foo",
			"client_id":     c.ClientID,
			"redirect_uri":  c.RedirectURI,
		},
		Username: c.ClientID,
		Password: c.ClientSecret,
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "unsupported_response_type", gjson.Get(r.Body.String(), "error").Str)
		},
	})
}
