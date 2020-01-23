package oauth2test

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
)

// PasswordGrantTest tests the password grant.
func PasswordGrantTest(t *testing.T, spec *Spec) {
	// invalid client secret
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
		Username: spec.ConfidentialClientID,
		Password: "invalid",
		Form: map[string]string{
			"grant_type": "password",
			"username":   spec.ResourceOwnerUsername,
			"password":   spec.ResourceOwnerPassword,
			"scope":      spec.ValidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_client", jsonFieldString(r, "error"), debug(r))
		},
	})

	// invalid username
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type": "password",
			"username":   "invalid",
			"password":   spec.ResourceOwnerPassword,
			"scope":      spec.ValidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusForbidden, r.Code, debug(r))
			assert.Equal(t, "access_denied", jsonFieldString(r, "error"), debug(r))
		},
	})

	// invalid password
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type": "password",
			"username":   spec.ResourceOwnerUsername,
			"password":   "invalid",
			"scope":      spec.ValidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusForbidden, r.Code, debug(r))
			assert.Equal(t, "access_denied", jsonFieldString(r, "error"), debug(r))
		},
	})

	// invalid scope
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type": "password",
			"username":   spec.ResourceOwnerUsername,
			"password":   spec.ResourceOwnerPassword,
			"scope":      spec.InvalidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_scope", jsonFieldString(r, "error"), debug(r))
		},
	})

	// exceeding scope
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type": "password",
			"username":   spec.ResourceOwnerUsername,
			"password":   spec.ResourceOwnerPassword,
			"scope":      spec.ExceedingScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_scope", jsonFieldString(r, "error"), debug(r))
		},
	})

	var accessToken, refreshToken string

	// get access token
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type": "password",
			"username":   spec.ResourceOwnerUsername,
			"password":   spec.ResourceOwnerPassword,
			"scope":      spec.ValidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusOK, r.Code, debug(r))
			assert.Equal(t, "bearer", jsonFieldString(r, "token_type"), debug(r))
			assert.Equal(t, spec.ValidScope, jsonFieldString(r, "scope"), debug(r))
			assert.Equal(t, float64(spec.ExpectedExpiresIn), jsonFieldFloat(r, "expires_in"), debug(r))

			accessToken = jsonFieldString(r, "access_token")
			assert.NotEmpty(t, accessToken, debug(r))

			refreshToken = jsonFieldString(r, "refresh_token")
			assert.NotEmpty(t, refreshToken, debug(r))
		},
	})

	// test access token
	AccessTokenTest(t, spec, accessToken)

	// test refresh token if present
	if refreshToken != "" {
		RefreshTokenTest(t, spec, refreshToken)
	}
}

// ClientCredentialsGrantTest tests the client credentials grant.
func ClientCredentialsGrantTest(t *testing.T, spec *Spec) {
	// invalid client secret
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
		Username: spec.ConfidentialClientID,
		Password: "invalid",
		Form: map[string]string{
			"grant_type": "client_credentials",
			"scope":      spec.ValidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_client", jsonFieldString(r, "error"), debug(r))
			assert.NotEmpty(t, auth(r, "realm"), debug(r))
		},
	})

	// public client
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
		Username: spec.PublicClientID,
		Form: map[string]string{
			"grant_type": "client_credentials",
			"scope":      spec.ValidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_client", jsonFieldString(r, "error"), debug(r))
			assert.NotEmpty(t, auth(r, "realm"), debug(r))
		},
	})

	// invalid scope
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type": "client_credentials",
			"scope":      spec.InvalidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_scope", jsonFieldString(r, "error"), debug(r))
		},
	})

	// exceeding scope
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type": "client_credentials",
			"scope":      spec.ExceedingScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_scope", jsonFieldString(r, "error"), debug(r))
		},
	})

	var accessToken, refreshToken string

	// get access token
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type": "client_credentials",
			"scope":      spec.ValidScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusOK, r.Code, debug(r))
			assert.Equal(t, "bearer", jsonFieldString(r, "token_type"), debug(r))
			assert.Equal(t, spec.ValidScope, jsonFieldString(r, "scope"), debug(r))
			assert.Equal(t, float64(spec.ExpectedExpiresIn), jsonFieldFloat(r, "expires_in"), debug(r))

			accessToken = jsonFieldString(r, "access_token")
			assert.NotEmpty(t, accessToken, debug(r))

			refreshToken = jsonFieldString(r, "refresh_token")
			assert.NotEmpty(t, refreshToken, debug(r))
		},
	})

	// test access token
	AccessTokenTest(t, spec, accessToken)

	// test refresh token if present
	if refreshToken != "" {
		RefreshTokenTest(t, spec, refreshToken)
	}
}

// ImplicitGrantTest tests the implicit grant.
func ImplicitGrantTest(t *testing.T, spec *Spec) {
	// invalid scope
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.AuthorizeEndpoint,
		Form: extend(spec.ValidAuthorizationParams, map[string]string{
			"response_type": "token",
			"client_id":     spec.ConfidentialClientID,
			"redirect_uri":  spec.PrimaryRedirectURI,
			"scope":         spec.InvalidScope,
			"state":         "xyz",
		}),
		Header: extend(spec.ValidAuthorizationHeaders, nil),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusSeeOther, r.Code, debug(r))
			assert.Equal(t, "invalid_scope", fragment(r, "error"), debug(r))
			assert.Equal(t, "xyz", fragment(r, "state"), debug(r))
		},
	})

	// exceeding scope
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.AuthorizeEndpoint,
		Form: extend(spec.ValidAuthorizationParams, map[string]string{
			"response_type": "token",
			"client_id":     spec.ConfidentialClientID,
			"redirect_uri":  spec.PrimaryRedirectURI,
			"scope":         spec.ExceedingScope,
			"state":         "xyz",
		}),
		Header: extend(spec.ValidAuthorizationHeaders, nil),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusSeeOther, r.Code, debug(r))
			assert.Equal(t, "invalid_scope", fragment(r, "error"), debug(r))
			assert.Equal(t, "xyz", fragment(r, "state"), debug(r))
		},
	})

	// access denied
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.AuthorizeEndpoint,
		Form: map[string]string{
			"response_type": "token",
			"client_id":     spec.ConfidentialClientID,
			"redirect_uri":  spec.PrimaryRedirectURI,
			"scope":         spec.ValidScope,
			"state":         "xyz",
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusSeeOther, r.Code, debug(r))
			assert.Equal(t, "access_denied", fragment(r, "error"), debug(r))
			assert.Equal(t, "xyz", fragment(r, "state"), debug(r))
		},
	})

	// invalid password
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.AuthorizeEndpoint,
		Form: extend(spec.InvalidAuthorizationParams, map[string]string{
			"response_type": "token",
			"client_id":     spec.ConfidentialClientID,
			"redirect_uri":  spec.PrimaryRedirectURI,
			"scope":         spec.ValidScope,
			"state":         "xyz",
		}),
		Header: extend(spec.InvalidAuthorizationHeaders, nil),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusSeeOther, r.Code, debug(r))
			assert.Equal(t, "access_denied", fragment(r, "error"), debug(r))
			assert.Equal(t, "xyz", fragment(r, "state"), debug(r))
		},
	})

	var accessToken string

	// get access token
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.AuthorizeEndpoint,
		Form: extend(spec.ValidAuthorizationParams, map[string]string{
			"response_type": "token",
			"client_id":     spec.ConfidentialClientID,
			"redirect_uri":  spec.PrimaryRedirectURI,
			"scope":         spec.ValidScope,
			"state":         "xyz",
		}),
		Header: extend(spec.ValidAuthorizationHeaders, nil),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusSeeOther, r.Code, debug(r))
			assert.Equal(t, "bearer", fragment(r, "token_type"), debug(r))
			assert.Equal(t, spec.ValidScope, fragment(r, "scope"), debug(r))
			assert.Equal(t, strconv.Itoa(spec.ExpectedExpiresIn), fragment(r, "expires_in"), debug(r))
			assert.Equal(t, "xyz", fragment(r, "state"), debug(r))
			assert.Empty(t, fragment(r, "refresh_token"), debug(r))

			accessToken = fragment(r, "access_token")
			assert.NotEmpty(t, accessToken, debug(r))
		},
	})

	// test access token
	AccessTokenTest(t, spec, accessToken)
}

// AuthorizationCodeGrantTest tests the authorization code grant.
func AuthorizationCodeGrantTest(t *testing.T, spec *Spec) {
	// invalid scope
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.AuthorizeEndpoint,
		Form: extend(spec.ValidAuthorizationParams, map[string]string{
			"response_type": "code",
			"client_id":     spec.ConfidentialClientID,
			"redirect_uri":  spec.PrimaryRedirectURI,
			"scope":         spec.InvalidScope,
			"state":         "xyz",
		}),
		Header: extend(spec.ValidAuthorizationHeaders, nil),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusSeeOther, r.Code, debug(r))
			assert.Equal(t, "invalid_scope", query(r, "error"), debug(r))
			assert.Equal(t, "xyz", query(r, "state"), debug(r))
		},
	})

	// exceeding scope
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.AuthorizeEndpoint,
		Form: extend(spec.ValidAuthorizationParams, map[string]string{
			"response_type": "code",
			"client_id":     spec.ConfidentialClientID,
			"redirect_uri":  spec.PrimaryRedirectURI,
			"scope":         spec.ExceedingScope,
			"state":         "xyz",
		}),
		Header: extend(spec.ValidAuthorizationHeaders, nil),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusSeeOther, r.Code, debug(r))
			assert.Equal(t, "invalid_scope", query(r, "error"), debug(r))
			assert.Equal(t, "xyz", query(r, "state"), debug(r))
		},
	})

	// access denied
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.AuthorizeEndpoint,
		Form: map[string]string{
			"response_type": "code",
			"client_id":     spec.ConfidentialClientID,
			"redirect_uri":  spec.PrimaryRedirectURI,
			"scope":         spec.ValidScope,
			"state":         "xyz",
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusSeeOther, r.Code, debug(r))
			assert.Equal(t, "access_denied", query(r, "error"), debug(r))
			assert.Equal(t, "xyz", query(r, "state"), debug(r))
		},
	})

	// invalid password
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.AuthorizeEndpoint,
		Form: extend(spec.InvalidAuthorizationParams, map[string]string{
			"response_type": "code",
			"client_id":     spec.ConfidentialClientID,
			"redirect_uri":  spec.PrimaryRedirectURI,
			"scope":         spec.ValidScope,
			"state":         "xyz",
		}),
		Header: extend(spec.InvalidAuthorizationHeaders, nil),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusSeeOther, r.Code, debug(r))
			assert.Equal(t, "access_denied", query(r, "error"), debug(r))
			assert.Equal(t, "xyz", query(r, "state"), debug(r))
		},
	})

	var authorizationCode string

	// get authorization code
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.AuthorizeEndpoint,
		Form: extend(spec.ValidAuthorizationParams, map[string]string{
			"response_type": "code",
			"client_id":     spec.ConfidentialClientID,
			"redirect_uri":  spec.PrimaryRedirectURI,
			"scope":         spec.ValidScope,
			"state":         "xyz",
		}),
		Header: extend(spec.ValidAuthorizationHeaders, nil),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusSeeOther, r.Code, debug(r))
			assert.Equal(t, "xyz", query(r, "state"), debug(r))

			authorizationCode = query(r, "code")
			assert.NotEmpty(t, authorizationCode, debug(r))
		},
	})

	// invalid client secret
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
		Username: spec.ConfidentialClientID,
		Password: "invalid",
		Form: map[string]string{
			"grant_type":   "authorization_code",
			"scope":        spec.ValidScope,
			"code":         spec.InvalidAuthorizationCode,
			"redirect_uri": spec.PrimaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_client", jsonFieldString(r, "error"), debug(r))
		},
	})

	// invalid authorization code
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type":   "authorization_code",
			"scope":        spec.ValidScope,
			"code":         spec.InvalidAuthorizationCode,
			"redirect_uri": spec.PrimaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// unknown authorization code
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type":   "authorization_code",
			"scope":        spec.ValidScope,
			"code":         spec.UnknownAuthorizationCode,
			"redirect_uri": spec.PrimaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_grant", jsonFieldString(r, "error"), debug(r))
		},
	})

	// expired authorization code
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type":   "authorization_code",
			"scope":        spec.ValidScope,
			"code":         spec.ExpiredAuthorizationCode,
			"redirect_uri": spec.PrimaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_grant", jsonFieldString(r, "error"), debug(r))
		},
	})

	// wrong client
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
		Username: spec.PublicClientID,
		Form: map[string]string{
			"grant_type":   "authorization_code",
			"scope":        spec.ValidScope,
			"code":         authorizationCode,
			"redirect_uri": spec.PrimaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_grant", jsonFieldString(r, "error"), debug(r))
		},
	})

	// wrong redirect uri
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type":   "authorization_code",
			"scope":        spec.ValidScope,
			"code":         authorizationCode,
			"redirect_uri": spec.SecondaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_grant", jsonFieldString(r, "error"), debug(r))
		},
	})

	var accessToken, refreshToken string

	// get access token
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type":   "authorization_code",
			"scope":        spec.ValidScope,
			"code":         authorizationCode,
			"redirect_uri": spec.PrimaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusOK, r.Code, debug(r))
			assert.Equal(t, "bearer", jsonFieldString(r, "token_type"), debug(r))
			assert.Equal(t, spec.ValidScope, jsonFieldString(r, "scope"), debug(r))
			assert.Equal(t, float64(spec.ExpectedExpiresIn), jsonFieldFloat(r, "expires_in"), debug(r))

			accessToken = jsonFieldString(r, "access_token")
			assert.NotEmpty(t, accessToken, debug(r))

			refreshToken = jsonFieldString(r, "refresh_token")
			assert.NotEmpty(t, refreshToken, debug(r))
		},
	})

	// test access token
	AccessTokenTest(t, spec, accessToken)

	// test refresh token if present
	if refreshToken != "" {
		RefreshTokenTest(t, spec, refreshToken)
	}

	/* code replay attack */

	// get authorization code
	Do(spec.Handler, &Request{
		Method: "POST",
		Path:   spec.AuthorizeEndpoint,
		Form: extend(spec.ValidAuthorizationParams, map[string]string{
			"response_type": "code",
			"client_id":     spec.ConfidentialClientID,
			"redirect_uri":  spec.PrimaryRedirectURI,
			"scope":         spec.ValidScope,
			"state":         "xyz",
		}),
		Header: extend(spec.ValidAuthorizationHeaders, nil),
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusSeeOther, r.Code, debug(r))
			assert.Equal(t, "xyz", query(r, "state"), debug(r))

			authorizationCode = query(r, "code")
			assert.NotEmpty(t, authorizationCode, debug(r))
		},
	})

	// get access token
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type":   "authorization_code",
			"scope":        spec.ValidScope,
			"code":         authorizationCode,
			"redirect_uri": spec.PrimaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusOK, r.Code, debug(r))
			assert.Equal(t, "bearer", jsonFieldString(r, "token_type"), debug(r))
			assert.Equal(t, spec.ValidScope, jsonFieldString(r, "scope"), debug(r))
			assert.Equal(t, float64(spec.ExpectedExpiresIn), jsonFieldFloat(r, "expires_in"), debug(r))

			accessToken = jsonFieldString(r, "access_token")
			assert.NotEmpty(t, accessToken, debug(r))

			refreshToken = jsonFieldString(r, "refresh_token")
			assert.NotEmpty(t, refreshToken, debug(r))
		},
	})

	// get access token
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type":   "authorization_code",
			"scope":        spec.ValidScope,
			"code":         authorizationCode,
			"redirect_uri": spec.PrimaryRedirectURI,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_grant", jsonFieldString(r, "error"), debug(r))
		},
	})

	// check if code replay mitigation is supported
	if spec.CodeReplayMitigation {
		// check access token
		Do(spec.Handler, &Request{
			Method: "GET",
			Path:   spec.ProtectedResource,
			Header: map[string]string{
				"Authorization": "Bearer " + accessToken,
			},
			Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
				assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			},
		})

		// check refresh token
		Do(spec.Handler, &Request{
			Method:   "POST",
			Path:     spec.TokenEndpoint,
			Username: spec.ConfidentialClientID,
			Password: spec.ConfidentialClientSecret,
			Form: map[string]string{
				"grant_type":    "refresh_token",
				"refresh_token": refreshToken,
			},
			Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
				assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
				assert.Equal(t, "invalid_grant", jsonFieldString(r, "error"), debug(r))
			},
		})
	}
}

// RefreshTokenGrantTest tests the refresh token grant.
func RefreshTokenGrantTest(t *testing.T, spec *Spec) {
	// invalid client secret
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
		Username: spec.ConfidentialClientID,
		Password: "invalid",
		Form: map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": spec.ValidRefreshToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusUnauthorized, r.Code, debug(r))
			assert.Equal(t, "invalid_client", jsonFieldString(r, "error"), debug(r))
		},
	})

	// invalid refresh token
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": spec.InvalidRefreshToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_request", jsonFieldString(r, "error"), debug(r))
		},
	})

	// unknown refresh token
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": spec.UnknownRefreshToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_grant", jsonFieldString(r, "error"), debug(r))
		},
	})

	// expired refresh token
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": spec.ExpiredRefreshToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_grant", jsonFieldString(r, "error"), debug(r))
		},
	})

	// wrong client
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
		Username: spec.PublicClientID,
		Form: map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": spec.ValidRefreshToken,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_grant", jsonFieldString(r, "error"), debug(r))
		},
	})

	// exceeding scope
	Do(spec.Handler, &Request{
		Method:   "POST",
		Path:     spec.TokenEndpoint,
		Username: spec.ConfidentialClientID,
		Password: spec.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": spec.ValidRefreshToken,
			"scope":         spec.ExceedingScope,
		},
		Callback: func(r *httptest.ResponseRecorder, rq *http.Request) {
			assert.Equal(t, http.StatusBadRequest, r.Code, debug(r))
			assert.Equal(t, "invalid_scope", jsonFieldString(r, "error"), debug(r))
		},
	})

	// test refresh token
	RefreshTokenTest(t, spec, spec.ValidRefreshToken)
}
