package spec

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/tidwall/gjson"
)

func PasswordGrantTest(t *testing.T, c *Config) {
	// invalid username
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ClientID,
		Password: c.ClientSecret,
		Form: map[string]string{
			"grant_type": "password",
			"username":   "invalid",
			"password":   c.OwnerPassword,
			"scope":      c.ValidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusForbidden, r.Code)
			assert.Equal(t, "access_denied", gjson.Get(r.Body.String(), "error").Str)
		},
	})

	// invalid password
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ClientID,
		Password: c.ClientSecret,
		Form: map[string]string{
			"grant_type": "password",
			"username":   c.OwnerUsername,
			"password":   "invalid",
			"scope":      c.ValidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusForbidden, r.Code)
			assert.Equal(t, "access_denied", gjson.Get(r.Body.String(), "error").Str)
		},
	})

	// invalid scope
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ClientID,
		Password: c.ClientSecret,
		Form: map[string]string{
			"grant_type": "password",
			"username":   c.OwnerUsername,
			"password":   c.OwnerPassword,
			"scope":      "invalid",
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_scope", gjson.Get(r.Body.String(), "error").Str)
		},
	})

	var accessToken, refreshToken string

	// get access token
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ClientID,
		Password: c.ClientSecret,
		Form: map[string]string{
			"grant_type": "password",
			"username":   c.OwnerUsername,
			"password":   c.OwnerPassword,
			"scope":      c.ValidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusOK, r.Code)
			assert.Equal(t, "bearer", gjson.Get(r.Body.String(), "token_type").String())
			assert.Equal(t, c.ValidScope, gjson.Get(r.Body.String(), "scope").String())
			assert.Equal(t, int64(c.ExpectedExpireIn), gjson.Get(r.Body.String(), "expires_in").Int())

			accessToken = gjson.Get(r.Body.String(), "access_token").String()
			refreshToken = gjson.Get(r.Body.String(), "refresh_token").String()
			assert.NotEmpty(t, accessToken)
		},
	})

	// test access token
	AccessTokenTest(t, c, accessToken)

	// test refresh token if present
	if refreshToken != "" {
		RefreshTokenTest(t, c, refreshToken)
	}
}
