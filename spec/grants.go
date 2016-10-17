package spec

import (
	"net/http"
	"net/http/httptest"
	"strconv"
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

func ClientCredentialsGrantTest(t *testing.T, c *Config) {
	// invalid client secret
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ClientID,
		Password: "invalid",
		Form: map[string]string{
			"grant_type": "client_credentials",
			"scope":      c.ValidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
			assert.Equal(t, "invalid_client", gjson.Get(r.Body.String(), "error").Str)
		},
	})

	// invalid scope
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ClientID,
		Password: c.ClientSecret,
		Form: map[string]string{
			"grant_type": "client_credentials",
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
			"grant_type": "client_credentials",
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

func ImplicitGrantTest(t *testing.T, c *Config) {
	// invalid scope
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: extend(c.CustomTokenAuthorization, map[string]string{
			"response_type": "token",
			"client_id":     c.ClientID,
			"redirect_uri":  c.RedirectURI,
			"scope":         "invalid",
			"state":         "foobar",
		}),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusFound, r.Code)
			assert.Equal(t, "invalid_scope", fragment(r, "error"))
			// TODO: assert.Equal(t, "foobar", fragment(r, "state"))
		},
	})

	var accessToken string

	// get access token
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: extend(c.CustomTokenAuthorization, map[string]string{
			"response_type": "token",
			"client_id":     c.ClientID,
			"redirect_uri":  c.RedirectURI,
			"scope":         c.ValidScope,
			"state":         "foobar",
		}),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusFound, r.Code)
			assert.Equal(t, "bearer", fragment(r, "token_type"))
			assert.Equal(t, c.ValidScope, fragment(r, "scope"))
			assert.Equal(t, strconv.Itoa(c.ExpectedExpireIn), fragment(r, "expires_in"))
			// TODO: assert.Equal(t, "foobar", fragment(r, "state"))

			accessToken = fragment(r, "access_token")
			assert.NotEmpty(t, accessToken)
		},
	})

	// test access token
	AccessTokenTest(t, c, accessToken)
}

func AuthorizationCodeGrantTest(t *testing.T, c *Config) {
	// invalid scope
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: extend(c.CustomCodeAuthorization, map[string]string{
			"response_type": "code",
			"client_id":     c.ClientID,
			"redirect_uri":  c.RedirectURI,
			"scope":         "invalid",
			"state":         "foobar",
		}),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusFound, r.Code)
			assert.Equal(t, "invalid_scope", query(r, "error"))
			// TODO: assert.Equal(t, "foobar", query(r, "state"))
		},
	})

	var authorizationCode string

	// get access token
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: extend(c.CustomCodeAuthorization, map[string]string{
			"response_type": "code",
			"client_id":     c.ClientID,
			"redirect_uri":  c.RedirectURI,
			"scope":         c.ValidScope,
			"state":         "foobar",
		}),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusFound, r.Code)
			// TODO: assert.Equal(t, "foobar", fragment(r, "state"))

			authorizationCode = query(r, "code")
			assert.NotEmpty(t, authorizationCode)
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
			"grant_type": "authorization_code",
			"scope":      c.ValidScope,
			"code":       authorizationCode,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusOK, r.Code)
			assert.Equal(t, "bearer", gjson.Get(r.Body.String(), "token_type").String())
			assert.Equal(t, c.ValidScope, gjson.Get(r.Body.String(), "scope").String())
			assert.Equal(t, int64(c.ExpectedExpireIn), gjson.Get(r.Body.String(), "expires_in").Int())

			accessToken = gjson.Get(r.Body.String(), "access_token").String()
			assert.NotEmpty(t, accessToken)
			refreshToken = gjson.Get(r.Body.String(), "refresh_token").String()
		},
	})

	// test access token
	AccessTokenTest(t, c, accessToken)

	// test refresh token if present
	if refreshToken != "" {
		RefreshTokenTest(t, c, refreshToken)
	}
}
