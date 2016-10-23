package spec

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gonfire/oauth2"
	"github.com/gonfire/oauth2/bearer"
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
			"password":   c.ResourceOwnerPassword,
			"scope":      c.ValidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusForbidden, r.Code, debug(r))
			assert.Equal(t, "access_denied", gjson.Get(r.Body.String(), "error").Str, debug(r))
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
			"username":   c.ResourceOwnerUsername,
			"password":   "invalid",
			"scope":      c.ValidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusForbidden, r.Code, debug(r))
			assert.Equal(t, "access_denied", gjson.Get(r.Body.String(), "error").Str, debug(r))
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
			"username":   c.ResourceOwnerUsername,
			"password":   c.ResourceOwnerPassword,
			"scope":      c.InvalidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_scope", gjson.Get(r.Body.String(), "error").Str, debug(r))
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
			"username":   c.ResourceOwnerUsername,
			"password":   c.ResourceOwnerPassword,
			"scope":      c.ExceedingScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_scope", gjson.Get(r.Body.String(), "error").Str, debug(r))
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
			"username":   c.ResourceOwnerUsername,
			"password":   c.ResourceOwnerPassword,
			"scope":      c.ValidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusOK, r.Code, debug(r))
			assert.Equal(t, bearer.TokenType, gjson.Get(r.Body.String(), "token_type").String(), debug(r))
			assert.Equal(t, c.ValidScope, gjson.Get(r.Body.String(), "scope").String(), debug(r))
			assert.Equal(t, int64(c.ExpectedExpireIn), gjson.Get(r.Body.String(), "expires_in").Int(), debug(r))

			accessToken = gjson.Get(r.Body.String(), "access_token").String()
			refreshToken = gjson.Get(r.Body.String(), "refresh_token").String()
			assert.NotEmpty(t, accessToken, debug(r))
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
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_client", gjson.Get(r.Body.String(), "error").Str, debug(r))
			assert.Contains(t, r.HeaderMap.Get("WWW-Authenticate"), `Basic realm=`, debug(r))
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
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_scope", gjson.Get(r.Body.String(), "error").Str, debug(r))
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
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_scope", gjson.Get(r.Body.String(), "error").Str, debug(r))
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
			assert.Equal(t, http.StatusOK, r.Code, debug(r))
			assert.Equal(t, "bearer", gjson.Get(r.Body.String(), "token_type").String(), debug(r))
			assert.Equal(t, c.ValidScope, gjson.Get(r.Body.String(), "scope").String(), debug(r))
			assert.Equal(t, int64(c.ExpectedExpireIn), gjson.Get(r.Body.String(), "expires_in").Int(), debug(r))

			accessToken = gjson.Get(r.Body.String(), "access_token").String()
			refreshToken = gjson.Get(r.Body.String(), "refresh_token").String()
			assert.NotEmpty(t, accessToken, debug(r))
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
		Form: extend(c.AuthorizationParams, map[string]string{
			"response_type": oauth2.TokenResponseType,
			"client_id":     c.PrimaryClientID,
			"redirect_uri":  c.PrimaryRedirectURI,
			"scope":         c.InvalidScope,
			"state":         "xyz",
		}),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusFound, r.Code, debug(r))
			assert.Equal(t, "invalid_scope", fragment(r, "error"), debug(r))
			assert.Equal(t, "xyz", fragment(r, "state"), debug(r))
		},
	})

	// exceeding scope
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: extend(c.AuthorizationParams, map[string]string{
			"response_type": oauth2.TokenResponseType,
			"client_id":     c.PrimaryClientID,
			"redirect_uri":  c.PrimaryRedirectURI,
			"scope":         c.ExceedingScope,
			"state":         "xyz",
		}),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusFound, r.Code, debug(r))
			assert.Equal(t, "invalid_scope", fragment(r, "error"), debug(r))
			assert.Equal(t, "xyz", fragment(r, "state"), debug(r))
		},
	})

	// access denied
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: map[string]string{
			"response_type": oauth2.TokenResponseType,
			"client_id":     c.PrimaryClientID,
			"redirect_uri":  c.PrimaryRedirectURI,
			"scope":         c.ValidScope,
			"state":         "xyz",
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusFound, r.Code, debug(r))
			assert.Equal(t, "access_denied", fragment(r, "error"), debug(r))
			assert.Equal(t, "xyz", fragment(r, "state"), debug(r))
		},
	})

	var accessToken string

	// get access token
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: extend(c.AuthorizationParams, map[string]string{
			"response_type": oauth2.TokenResponseType,
			"client_id":     c.PrimaryClientID,
			"redirect_uri":  c.PrimaryRedirectURI,
			"scope":         c.ValidScope,
			"state":         "xyz",
		}),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusFound, r.Code, debug(r))
			assert.Equal(t, bearer.TokenType, fragment(r, "token_type"), debug(r))
			assert.Equal(t, c.ValidScope, fragment(r, "scope"), debug(r))
			assert.Equal(t, strconv.Itoa(c.ExpectedExpireIn), fragment(r, "expires_in"), debug(r))
			assert.Equal(t, "xyz", fragment(r, "state"), debug(r))

			accessToken = fragment(r, "access_token")
			assert.NotEmpty(t, accessToken, debug(r))
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
		Form: extend(c.AuthorizationParams, map[string]string{
			"response_type": oauth2.CodeResponseType,
			"client_id":     c.PrimaryClientID,
			"redirect_uri":  c.PrimaryRedirectURI,
			"scope":         c.InvalidScope,
			"state":         "xyz",
		}),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusFound, r.Code, debug(r))
			assert.Equal(t, "invalid_scope", query(r, "error"), debug(r))
			assert.Equal(t, "xyz", query(r, "state"), debug(r))
		},
	})

	// exceeding scope
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: extend(c.AuthorizationParams, map[string]string{
			"response_type": oauth2.CodeResponseType,
			"client_id":     c.PrimaryClientID,
			"redirect_uri":  c.PrimaryRedirectURI,
			"scope":         c.ExceedingScope,
			"state":         "xyz",
		}),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusFound, r.Code, debug(r))
			assert.Equal(t, "invalid_scope", query(r, "error"), debug(r))
			assert.Equal(t, "xyz", query(r, "state"), debug(r))
		},
	})

	// access denied
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: map[string]string{
			"response_type": oauth2.CodeResponseType,
			"client_id":     c.PrimaryClientID,
			"redirect_uri":  c.PrimaryRedirectURI,
			"scope":         c.ValidScope,
			"state":         "xyz",
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusFound, r.Code, debug(r))
			assert.Equal(t, "access_denied", query(r, "error"), debug(r))
			assert.Equal(t, "xyz", query(r, "state"), debug(r))
		},
	})

	var authorizationCode string

	// get authorization code
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: extend(c.AuthorizationParams, map[string]string{
			"response_type": oauth2.CodeResponseType,
			"client_id":     c.PrimaryClientID,
			"redirect_uri":  c.PrimaryRedirectURI,
			"scope":         c.ValidScope,
			"state":         "xyz",
		}),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusFound, r.Code, debug(r))
			assert.Equal(t, "xyz", query(r, "state"), debug(r))

			authorizationCode = query(r, "code")
			assert.NotEmpty(t, authorizationCode, debug(r))
		},
	})

	// invalid authorization code
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.PrimaryClientID,
		Password: c.PrimaryClientSecret,
		Form: map[string]string{
			"grant_type":   oauth2.AuthorizationCodeGrantType,
			"scope":        c.ValidScope,
			"code":         c.InvalidAuthorizationCode,
			"redirect_uri": c.PrimaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", gjson.Get(r.Body.String(), "error").Str, debug(r))
		},
	})

	// unknown authorization code
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.PrimaryClientID,
		Password: c.PrimaryClientSecret,
		Form: map[string]string{
			"grant_type":   oauth2.AuthorizationCodeGrantType,
			"scope":        c.ValidScope,
			"code":         c.UnknownAuthorizationCode,
			"redirect_uri": c.PrimaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_grant", gjson.Get(r.Body.String(), "error").Str, debug(r))
		},
	})

	// expired authorization code
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.PrimaryClientID,
		Password: c.PrimaryClientSecret,
		Form: map[string]string{
			"grant_type":   oauth2.AuthorizationCodeGrantType,
			"scope":        c.ValidScope,
			"code":         c.ExpiredAuthorizationCode,
			"redirect_uri": c.PrimaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_grant", gjson.Get(r.Body.String(), "error").Str, debug(r))
		},
	})

	// wrong client
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.SecondaryClientID,
		Password: c.SecondaryClientSecret,
		Form: map[string]string{
			"grant_type":   oauth2.AuthorizationCodeGrantType,
			"scope":        c.ValidScope,
			"code":         authorizationCode,
			"redirect_uri": c.PrimaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_grant", gjson.Get(r.Body.String(), "error").Str, debug(r))
		},
	})

	// wrong redirect uri
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.PrimaryClientID,
		Password: c.PrimaryClientSecret,
		Form: map[string]string{
			"grant_type":   oauth2.AuthorizationCodeGrantType,
			"scope":        c.ValidScope,
			"code":         authorizationCode,
			"redirect_uri": c.SecondaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_grant", gjson.Get(r.Body.String(), "error").Str, debug(r))
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
			"grant_type":   oauth2.AuthorizationCodeGrantType,
			"scope":        c.ValidScope,
			"code":         authorizationCode,
			"redirect_uri": c.PrimaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusOK, r.Code, debug(r))
			assert.Equal(t, bearer.TokenType, gjson.Get(r.Body.String(), "token_type").String(), debug(r))
			assert.Equal(t, c.ValidScope, gjson.Get(r.Body.String(), "scope").String(), debug(r))
			assert.Equal(t, int64(c.ExpectedExpireIn), gjson.Get(r.Body.String(), "expires_in").Int(), debug(r))

			accessToken = gjson.Get(r.Body.String(), "access_token").String()
			assert.NotEmpty(t, accessToken, debug(r))
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
			"refresh_token": c.InvalidRefreshToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", gjson.Get(r.Body.String(), "error").String(), debug(r))
		},
	})

	// unknown refresh token
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.PrimaryClientID,
		Password: c.PrimaryClientSecret,
		Form: map[string]string{
			"grant_type":    oauth2.RefreshTokenGrantType,
			"refresh_token": c.UnknownRefreshToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_grant", gjson.Get(r.Body.String(), "error").String(), debug(r))
		},
	})

	// expired refresh token
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.PrimaryClientID,
		Password: c.PrimaryClientSecret,
		Form: map[string]string{
			"grant_type":    oauth2.RefreshTokenGrantType,
			"refresh_token": c.ExpiredRefreshToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_grant", gjson.Get(r.Body.String(), "error").String(), debug(r))
		},
	})

	// wrong client
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.SecondaryClientID,
		Password: c.SecondaryClientSecret,
		Form: map[string]string{
			"grant_type":    oauth2.RefreshTokenGrantType,
			"refresh_token": c.ValidRefreshToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_grant", gjson.Get(r.Body.String(), "error").String(), debug(r))
		},
	})

	// exceeding scope
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.PrimaryClientID,
		Password: c.PrimaryClientSecret,
		Form: map[string]string{
			"grant_type":    oauth2.RefreshTokenGrantType,
			"refresh_token": c.ValidRefreshToken,
			"scope":         c.ExceedingScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_scope", gjson.Get(r.Body.String(), "error").String(), debug(r))
		},
	})

	// test refresh token
	RefreshTokenTest(t, c, c.ValidRefreshToken)

	// test refresh token invalidation
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.PrimaryClientID,
		Password: c.PrimaryClientSecret,
		Form: map[string]string{
			"grant_type":    oauth2.RefreshTokenGrantType,
			"refresh_token": c.ValidRefreshToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_grant", gjson.Get(r.Body.String(), "error").String(), debug(r))
		},
	})
}
