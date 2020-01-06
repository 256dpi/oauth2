package spec

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

// PasswordGrantTest tests the password grant.
func PasswordGrantTest(t *testing.T, c *Config) {
	// invalid client secret
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ConfidentialClientID,
		Password: "invalid",
		Form: map[string]string{
			"grant_type": "password",
			"username":   c.ResourceOwnerUsername,
			"password":   c.ResourceOwnerPassword,
			"scope":      c.ValidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
			assert.Equal(t, "invalid_client", jsonFieldString(r, "error"))
		},
	})

	// invalid username
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type": "password",
			"username":   "invalid",
			"password":   c.ResourceOwnerPassword,
			"scope":      c.ValidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusForbidden, r.Code)
			assert.Equal(t, "access_denied", jsonFieldString(r, "error"))
		},
	})

	// invalid password
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type": "password",
			"username":   c.ResourceOwnerUsername,
			"password":   "invalid",
			"scope":      c.ValidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusForbidden, r.Code)
			assert.Equal(t, "access_denied", jsonFieldString(r, "error"))
		},
	})

	// invalid scope
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type": "password",
			"username":   c.ResourceOwnerUsername,
			"password":   c.ResourceOwnerPassword,
			"scope":      c.InvalidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_scope", jsonFieldString(r, "error"))
		},
	})

	// exceeding scope
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type": "password",
			"username":   c.ResourceOwnerUsername,
			"password":   c.ResourceOwnerPassword,
			"scope":      c.ExceedingScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_scope", jsonFieldString(r, "error"))
		},
	})

	var accessToken, refreshToken string

	// get access token
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type": "password",
			"username":   c.ResourceOwnerUsername,
			"password":   c.ResourceOwnerPassword,
			"scope":      c.ValidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusOK, r.Code, debug(r))
			assert.Equal(t, "bearer", jsonFieldString(r, "token_type"))
			assert.Equal(t, c.ValidScope, jsonFieldString(r, "scope"))
			assert.Equal(t, float64(c.ExpectedExpiresIn), jsonFieldFloat(r, "expires_in"))

			accessToken = jsonFieldString(r, "access_token")
			assert.NotEmpty(t, accessToken)

			refreshToken = jsonFieldString(r, "refresh_token")
			assert.NotEmpty(t, refreshToken)
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
		Username: c.ConfidentialClientID,
		Password: "invalid",
		Form: map[string]string{
			"grant_type": "client_credentials",
			"scope":      c.ValidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
			assert.Equal(t, "invalid_client", jsonFieldString(r, "error"))
			assert.NotEmpty(t, auth(r, "realm"))
		},
	})

	// public client
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.PublicClientID,
		Form: map[string]string{
			"grant_type": "client_credentials",
			"scope":      c.ValidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
			assert.Equal(t, "invalid_client", jsonFieldString(r, "error"))
			assert.NotEmpty(t, auth(r, "realm"))
		},
	})

	// invalid scope
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type": "client_credentials",
			"scope":      c.InvalidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_scope", jsonFieldString(r, "error"))
		},
	})

	// exceeding scope
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type": "client_credentials",
			"scope":      c.ExceedingScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_scope", jsonFieldString(r, "error"))
		},
	})

	var accessToken, refreshToken string

	// get access token
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type": "client_credentials",
			"scope":      c.ValidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusOK, r.Code, debug(r))
			assert.Equal(t, "bearer", jsonFieldString(r, "token_type"))
			assert.Equal(t, c.ValidScope, jsonFieldString(r, "scope"))
			assert.Equal(t, float64(c.ExpectedExpiresIn), jsonFieldFloat(r, "expires_in"))

			accessToken = jsonFieldString(r, "access_token")
			assert.NotEmpty(t, accessToken)

			refreshToken = jsonFieldString(r, "refresh_token")
			assert.NotEmpty(t, refreshToken)
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
		Form: extend(c.ValidAuthorizationParams, map[string]string{
			"response_type": "token",
			"client_id":     c.ConfidentialClientID,
			"redirect_uri":  c.PrimaryRedirectURI,
			"scope":         c.InvalidScope,
			"state":         "xyz",
		}),
		Header: extend(c.ValidAuthorizationHeaders, nil),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusSeeOther, r.Code)
			assert.Equal(t, "invalid_scope", fragment(r, "error"))
			assert.Equal(t, "xyz", fragment(r, "state"))
		},
	})

	// exceeding scope
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: extend(c.ValidAuthorizationParams, map[string]string{
			"response_type": "token",
			"client_id":     c.ConfidentialClientID,
			"redirect_uri":  c.PrimaryRedirectURI,
			"scope":         c.ExceedingScope,
			"state":         "xyz",
		}),
		Header: extend(c.ValidAuthorizationHeaders, nil),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusSeeOther, r.Code)
			assert.Equal(t, "invalid_scope", fragment(r, "error"))
			assert.Equal(t, "xyz", fragment(r, "state"))
		},
	})

	// access denied
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: map[string]string{
			"response_type": "token",
			"client_id":     c.ConfidentialClientID,
			"redirect_uri":  c.PrimaryRedirectURI,
			"scope":         c.ValidScope,
			"state":         "xyz",
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusSeeOther, r.Code)
			assert.Equal(t, "access_denied", fragment(r, "error"))
			assert.Equal(t, "xyz", fragment(r, "state"))
		},
	})

	// invalid password
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: extend(c.InvalidAuthorizationParams, map[string]string{
			"response_type": "token",
			"client_id":     c.ConfidentialClientID,
			"redirect_uri":  c.PrimaryRedirectURI,
			"scope":         c.ValidScope,
			"state":         "xyz",
		}),
		Header: extend(c.InvalidAuthorizationHeaders, nil),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusSeeOther, r.Code)
			assert.Equal(t, "access_denied", fragment(r, "error"))
			assert.Equal(t, "xyz", fragment(r, "state"))
		},
	})

	var accessToken string

	// get access token
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: extend(c.ValidAuthorizationParams, map[string]string{
			"response_type": "token",
			"client_id":     c.ConfidentialClientID,
			"redirect_uri":  c.PrimaryRedirectURI,
			"scope":         c.ValidScope,
			"state":         "xyz",
		}),
		Header: extend(c.ValidAuthorizationHeaders, nil),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusSeeOther, r.Code, debug(r))
			assert.Equal(t, "bearer", fragment(r, "token_type"))
			assert.Equal(t, c.ValidScope, fragment(r, "scope"))
			assert.Equal(t, strconv.Itoa(c.ExpectedExpiresIn), fragment(r, "expires_in"))
			assert.Equal(t, "xyz", fragment(r, "state"))
			assert.Empty(t, fragment(r, "refresh_token"))

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
		Form: extend(c.ValidAuthorizationParams, map[string]string{
			"response_type": "code",
			"client_id":     c.ConfidentialClientID,
			"redirect_uri":  c.PrimaryRedirectURI,
			"scope":         c.InvalidScope,
			"state":         "xyz",
		}),
		Header: extend(c.ValidAuthorizationHeaders, nil),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusSeeOther, r.Code)
			assert.Equal(t, "invalid_scope", query(r, "error"))
			assert.Equal(t, "xyz", query(r, "state"))
		},
	})

	// exceeding scope
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: extend(c.ValidAuthorizationParams, map[string]string{
			"response_type": "code",
			"client_id":     c.ConfidentialClientID,
			"redirect_uri":  c.PrimaryRedirectURI,
			"scope":         c.ExceedingScope,
			"state":         "xyz",
		}),
		Header: extend(c.ValidAuthorizationHeaders, nil),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusSeeOther, r.Code)
			assert.Equal(t, "invalid_scope", query(r, "error"))
			assert.Equal(t, "xyz", query(r, "state"))
		},
	})

	// access denied
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: map[string]string{
			"response_type": "code",
			"client_id":     c.ConfidentialClientID,
			"redirect_uri":  c.PrimaryRedirectURI,
			"scope":         c.ValidScope,
			"state":         "xyz",
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusSeeOther, r.Code)
			assert.Equal(t, "access_denied", query(r, "error"))
			assert.Equal(t, "xyz", query(r, "state"))
		},
	})

	// invalid password
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: extend(c.InvalidAuthorizationParams, map[string]string{
			"response_type": "code",
			"client_id":     c.ConfidentialClientID,
			"redirect_uri":  c.PrimaryRedirectURI,
			"scope":         c.ValidScope,
			"state":         "xyz",
		}),
		Header: extend(c.InvalidAuthorizationHeaders, nil),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusSeeOther, r.Code)
			assert.Equal(t, "access_denied", query(r, "error"))
			assert.Equal(t, "xyz", query(r, "state"))
		},
	})

	var authorizationCode string

	// get authorization code
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: extend(c.ValidAuthorizationParams, map[string]string{
			"response_type": "code",
			"client_id":     c.ConfidentialClientID,
			"redirect_uri":  c.PrimaryRedirectURI,
			"scope":         c.ValidScope,
			"state":         "xyz",
		}),
		Header: extend(c.ValidAuthorizationHeaders, nil),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusSeeOther, r.Code)
			assert.Equal(t, "xyz", query(r, "state"))

			authorizationCode = query(r, "code")
			assert.NotEmpty(t, authorizationCode)
		},
	})

	// invalid client secret
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ConfidentialClientID,
		Password: "invalid",
		Form: map[string]string{
			"grant_type":   "authorization_code",
			"scope":        c.ValidScope,
			"code":         c.InvalidAuthorizationCode,
			"redirect_uri": c.PrimaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
			assert.Equal(t, "invalid_client", jsonFieldString(r, "error"))
		},
	})

	// invalid authorization code
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type":   "authorization_code",
			"scope":        c.ValidScope,
			"code":         c.InvalidAuthorizationCode,
			"redirect_uri": c.PrimaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"))
		},
	})

	// unknown authorization code
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type":   "authorization_code",
			"scope":        c.ValidScope,
			"code":         c.UnknownAuthorizationCode,
			"redirect_uri": c.PrimaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_grant", jsonFieldString(r, "error"))
		},
	})

	// expired authorization code
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type":   "authorization_code",
			"scope":        c.ValidScope,
			"code":         c.ExpiredAuthorizationCode,
			"redirect_uri": c.PrimaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_grant", jsonFieldString(r, "error"))
		},
	})

	// wrong client
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.PublicClientID,
		Form: map[string]string{
			"grant_type":   "authorization_code",
			"scope":        c.ValidScope,
			"code":         authorizationCode,
			"redirect_uri": c.PrimaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_grant", jsonFieldString(r, "error"))
		},
	})

	// wrong redirect uri
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type":   "authorization_code",
			"scope":        c.ValidScope,
			"code":         authorizationCode,
			"redirect_uri": c.SecondaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_grant", jsonFieldString(r, "error"))
		},
	})

	var accessToken, refreshToken string

	// get access token
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type":   "authorization_code",
			"scope":        c.ValidScope,
			"code":         authorizationCode,
			"redirect_uri": c.PrimaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusOK, r.Code, debug(r))
			assert.Equal(t, "bearer", jsonFieldString(r, "token_type"))
			assert.Equal(t, c.ValidScope, jsonFieldString(r, "scope"))
			assert.Equal(t, float64(c.ExpectedExpiresIn), jsonFieldFloat(r, "expires_in"))

			accessToken = jsonFieldString(r, "access_token")
			assert.NotEmpty(t, accessToken)

			refreshToken = jsonFieldString(r, "refresh_token")
			assert.NotEmpty(t, refreshToken)
		},
	})

	// test access token
	AccessTokenTest(t, c, accessToken)

	// test refresh token if present
	if refreshToken != "" {
		RefreshTokenTest(t, c, refreshToken)
	}

	/* code replay attack */

	// get authorization code
	Do(c.Handler, &Request{
		Method: "POST",
		Path:   c.AuthorizeEndpoint,
		Form: extend(c.ValidAuthorizationParams, map[string]string{
			"response_type": "code",
			"client_id":     c.ConfidentialClientID,
			"redirect_uri":  c.PrimaryRedirectURI,
			"scope":         c.ValidScope,
			"state":         "xyz",
		}),
		Header: extend(c.ValidAuthorizationHeaders, nil),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusSeeOther, r.Code)
			assert.Equal(t, "xyz", query(r, "state"))

			authorizationCode = query(r, "code")
			assert.NotEmpty(t, authorizationCode)
		},
	})

	// get access token
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type":   "authorization_code",
			"scope":        c.ValidScope,
			"code":         authorizationCode,
			"redirect_uri": c.PrimaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusOK, r.Code, debug(r))
			assert.Equal(t, "bearer", jsonFieldString(r, "token_type"))
			assert.Equal(t, c.ValidScope, jsonFieldString(r, "scope"))
			assert.Equal(t, float64(c.ExpectedExpiresIn), jsonFieldFloat(r, "expires_in"))

			accessToken = jsonFieldString(r, "access_token")
			assert.NotEmpty(t, accessToken)

			refreshToken = jsonFieldString(r, "refresh_token")
			assert.NotEmpty(t, refreshToken)
		},
	})

	// get access token
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type":   "authorization_code",
			"scope":        c.ValidScope,
			"code":         authorizationCode,
			"redirect_uri": c.PrimaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_grant", jsonFieldString(r, "error"))
		},
	})

	// check if code replay mitigation is supported
	if c.CodeReplayMitigation {
		// check access token
		Do(c.Handler, &Request{
			Method: "GET",
			Path:   c.ProtectedResource,
			Header: map[string]string{
				"Authorization": "Bearer " + accessToken,
			},
			Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
				assert.Equal(t, http.StatusUnauthorized, r.Code)
			},
		})

		// check refresh token
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
				assert.Equal(t, http.StatusBadRequest, r.Code)
				assert.Equal(t, "invalid_grant", jsonFieldString(r, "error"))
			},
		})
	}
}

// RefreshTokenGrantTest tests the refresh token grant.
func RefreshTokenGrantTest(t *testing.T, c *Config) {
	// invalid client secret
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ConfidentialClientID,
		Password: "invalid",
		Form: map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": c.ValidRefreshToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code)
			assert.Equal(t, "invalid_client", jsonFieldString(r, "error"))
		},
	})

	// invalid refresh token
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": c.InvalidRefreshToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"))
		},
	})

	// unknown refresh token
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": c.UnknownRefreshToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_grant", jsonFieldString(r, "error"))
		},
	})

	// expired refresh token
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": c.ExpiredRefreshToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_grant", jsonFieldString(r, "error"))
		},
	})

	// wrong client
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.PublicClientID,
		Form: map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": c.ValidRefreshToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_grant", jsonFieldString(r, "error"))
		},
	})

	// exceeding scope
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": c.ValidRefreshToken,
			"scope":         c.ExceedingScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code)
			assert.Equal(t, "invalid_scope", jsonFieldString(r, "error"))
		},
	})

	// test refresh token
	RefreshTokenTest(t, c, c.ValidRefreshToken)
}
