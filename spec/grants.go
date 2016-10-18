package spec

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gonfire/oauth2"
	"github.com/stretchr/testify/assert"
	"github.com/tidwall/gjson"
)

// PasswordGrantTest tests the password grant.
func PasswordGrantTest(t *testing.T, c *Config) {
	// invalid username
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.PrimaryClientID,
		Password: c.PrimaryClientSecret,
		Form: map[string]string{
			"grant_type": oauth2.PasswordGrantType,
			"username":   "invalid",
			"password":   c.PrimaryResourceOwnerPassword,
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
		Username: c.PrimaryClientID,
		Password: c.PrimaryClientSecret,
		Form: map[string]string{
			"grant_type": oauth2.PasswordGrantType,
			"username":   c.PrimaryResourceOwnerUsername,
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
		Username: c.PrimaryClientID,
		Password: c.PrimaryClientSecret,
		Form: map[string]string{
			"grant_type": oauth2.PasswordGrantType,
			"username":   c.PrimaryResourceOwnerUsername,
			"password":   c.PrimaryResourceOwnerPassword,
			"scope":      c.InvalidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_scope", gjson.Get(r.Body.String(), "error").Str)
		},
	})

	// exceeding scope
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.PrimaryClientID,
		Password: c.PrimaryClientSecret,
		Form: map[string]string{
			"grant_type": oauth2.PasswordGrantType,
			"username":   c.PrimaryResourceOwnerUsername,
			"password":   c.PrimaryResourceOwnerPassword,
			"scope":      c.ExceedingScope,
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
		Username: c.PrimaryClientID,
		Password: c.PrimaryClientSecret,
		Form: map[string]string{
			"grant_type": oauth2.PasswordGrantType,
			"username":   c.PrimaryResourceOwnerUsername,
			"password":   c.PrimaryResourceOwnerPassword,
			"scope":      c.ValidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusOK, r.Code)
			assert.Equal(t, oauth2.BearerTokenType, gjson.Get(r.Body.String(), "token_type").String())
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

// ClientCredentialsGrantTest tests the client credentials grant.
func ClientCredentialsGrantTest(t *testing.T, c *Config) {
	// invalid client secret
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.PrimaryClientID,
		Password: "invalid",
		Form: map[string]string{
			"grant_type": oauth2.ClientCredentialsGrantType,
			"scope":      c.ValidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
			assert.Equal(t, "invalid_client", gjson.Get(r.Body.String(), "error").Str)
			assert.Equal(t, `Basic realm="OAuth2"`, r.HeaderMap.Get("WWW-Authenticate"))
		},
	})

	// invalid scope
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.PrimaryClientID,
		Password: c.PrimaryClientSecret,
		Form: map[string]string{
			"grant_type": oauth2.ClientCredentialsGrantType,
			"scope":      c.InvalidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_scope", gjson.Get(r.Body.String(), "error").Str)
		},
	})

	// exceeding scope
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.PrimaryClientID,
		Password: c.PrimaryClientSecret,
		Form: map[string]string{
			"grant_type": oauth2.ClientCredentialsGrantType,
			"scope":      c.ExceedingScope,
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
		Username: c.PrimaryClientID,
		Password: c.PrimaryClientSecret,
		Form: map[string]string{
			"grant_type": oauth2.ClientCredentialsGrantType,
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

// ImplicitGrantTest tests the implicit grant.
func ImplicitGrantTest(t *testing.T, c *Config) {
	// invalid scope
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: extend(c.TokenAuthorizationParams, map[string]string{
			"response_type": oauth2.TokenResponseType,
			"client_id":     c.PrimaryClientID,
			"redirect_uri":  c.ValidRedirectURI,
			"scope":         c.InvalidScope,
			"state":         "xyz",
		}),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusFound, r.Code)
			assert.Equal(t, "invalid_scope", fragment(r, "error"))
			assert.Equal(t, "xyz", fragment(r, "state"))
		},
	})

	// exceeding scope
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: extend(c.TokenAuthorizationParams, map[string]string{
			"response_type": oauth2.TokenResponseType,
			"client_id":     c.PrimaryClientID,
			"redirect_uri":  c.ValidRedirectURI,
			"scope":         c.ExceedingScope,
			"state":         "xyz",
		}),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusFound, r.Code)
			assert.Equal(t, "invalid_scope", fragment(r, "error"))
			assert.Equal(t, "xyz", fragment(r, "state"))
		},
	})

	// access denied
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: map[string]string{
			"response_type": oauth2.TokenResponseType,
			"client_id":     c.PrimaryClientID,
			"redirect_uri":  c.ValidRedirectURI,
			"scope":         c.ValidScope,
			"state":         "xyz",
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusFound, r.Code)
			assert.Equal(t, "access_denied", fragment(r, "error"))
			assert.Equal(t, "xyz", fragment(r, "state"))
		},
	})

	var accessToken string

	// get access token
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: extend(c.TokenAuthorizationParams, map[string]string{
			"response_type": oauth2.TokenResponseType,
			"client_id":     c.PrimaryClientID,
			"redirect_uri":  c.ValidRedirectURI,
			"scope":         c.ValidScope,
			"state":         "xyz",
		}),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusFound, r.Code)
			assert.Equal(t, oauth2.BearerTokenType, fragment(r, "token_type"))
			assert.Equal(t, c.ValidScope, fragment(r, "scope"))
			assert.Equal(t, strconv.Itoa(c.ExpectedExpireIn), fragment(r, "expires_in"))
			assert.Equal(t, "xyz", fragment(r, "state"))

			accessToken = fragment(r, "access_token")
			assert.NotEmpty(t, accessToken)
		},
	})

	// test access token
	AccessTokenTest(t, c, accessToken)
}

// AuthorizationCodeGrantTest tests the authorization code grant.
func AuthorizationCodeGrantTest(t *testing.T, c *Config) {
	// invalid scope
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: extend(c.CodeAuthorizationParams, map[string]string{
			"response_type": oauth2.CodeResponseType,
			"client_id":     c.PrimaryClientID,
			"redirect_uri":  c.ValidRedirectURI,
			"scope":         c.InvalidScope,
			"state":         "xyz",
		}),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusFound, r.Code)
			assert.Equal(t, "invalid_scope", query(r, "error"))
			assert.Equal(t, "xyz", query(r, "state"))
		},
	})

	// exceeding scope
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: extend(c.CodeAuthorizationParams, map[string]string{
			"response_type": oauth2.CodeResponseType,
			"client_id":     c.PrimaryClientID,
			"redirect_uri":  c.ValidRedirectURI,
			"scope":         c.ExceedingScope,
			"state":         "xyz",
		}),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusFound, r.Code)
			assert.Equal(t, "invalid_scope", query(r, "error"))
			assert.Equal(t, "xyz", query(r, "state"))
		},
	})

	// access denied
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: map[string]string{
			"response_type": oauth2.CodeResponseType,
			"client_id":     c.PrimaryClientID,
			"redirect_uri":  c.ValidRedirectURI,
			"scope":         c.ValidScope,
			"state":         "xyz",
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusFound, r.Code)
			assert.Equal(t, "access_denied", query(r, "error"))
			assert.Equal(t, "xyz", query(r, "state"))
		},
	})

	var authorizationCode string

	// get authorization code
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: extend(c.CodeAuthorizationParams, map[string]string{
			"response_type": oauth2.CodeResponseType,
			"client_id":     c.PrimaryClientID,
			"redirect_uri":  c.ValidRedirectURI,
			"scope":         c.ValidScope,
			"state":         "xyz",
		}),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusFound, r.Code)
			assert.Equal(t, "xyz", query(r, "state"))

			authorizationCode = query(r, "code")
			assert.NotEmpty(t, authorizationCode)
		},
	})

	var accessToken, refreshToken string

	// invalid code
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.PrimaryClientID,
		Password: c.PrimaryClientSecret,
		Form: map[string]string{
			"grant_type":   oauth2.AuthorizationCodeGrantType,
			"scope":        c.ValidScope,
			"code":         "invalid",
			"redirect_uri": c.ValidRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_request", gjson.Get(r.Body.String(), "error").Str)
		},
	})

	// get access token
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.PrimaryClientID,
		Password: c.PrimaryClientSecret,
		Form: map[string]string{
			"grant_type":   oauth2.AuthorizationCodeGrantType,
			"scope":        c.ValidScope,
			"code":         authorizationCode,
			"redirect_uri": c.ValidRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusOK, r.Code)
			assert.Equal(t, oauth2.BearerTokenType, gjson.Get(r.Body.String(), "token_type").String())
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

// RefreshTokenGrantTest tests the refresh token grant.
func RefreshTokenGrantTest(t *testing.T, c *Config) {
	// invalid refresh token
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.PrimaryClientID,
		Password: c.PrimaryClientSecret,
		Form: map[string]string{
			"grant_type":    oauth2.RefreshTokenGrantType,
			"refresh_token": "invalid",
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_request", gjson.Get(r.Body.String(), "error").String())
		},
	})

	// invalid refresh token
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.PrimaryClientID,
		Password: c.PrimaryClientSecret,
		Form: map[string]string{
			"grant_type":    oauth2.RefreshTokenGrantType,
			"refresh_token": c.InvalidRefreshToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_grant", gjson.Get(r.Body.String(), "error").String())
		},
	})

	// test refresh token
	RefreshTokenTest(t, c, c.ValidRefreshToken)
}
