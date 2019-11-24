package spec

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
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
			if r.Code != http.StatusUnauthorized {
				t.Error("expected status unauthorized", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_client" {
				t.Error(`expected error to be "invalid_client"`, debug(r))
			}
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
			if r.Code != http.StatusForbidden {
				t.Error("expected status forbidden", debug(r))
			}

			if jsonFieldString(r, "error") != "access_denied" {
				t.Error(`expected error to be "access_denied"`, debug(r))
			}
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
			if r.Code != http.StatusForbidden {
				t.Error("expected status forbidden", debug(r))
			}

			if jsonFieldString(r, "error") != "access_denied" {
				t.Error(`expected error to be "access_denied"`, debug(r))
			}
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
			if r.Code != http.StatusBadRequest {
				t.Error("expected status bad request", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_scope" {
				t.Error(`expected error to be "invalid_scope"`, debug(r))
			}
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
			if r.Code != http.StatusBadRequest {
				t.Error("expected status bad request", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_scope" {
				t.Error(`expected error to be "invalid_scope"`, debug(r))
			}
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

			refreshToken = jsonFieldString(r, "refresh_token")
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
			if r.Code != http.StatusUnauthorized {
				t.Error("expected status unauthorized", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_client" {
				t.Error(`expected error to be "invalid_client"`, debug(r))
			}

			if !strings.HasPrefix(r.Header().Get("WWW-Authenticate"), "Basic realm=") {
				t.Error(`expected header WWW-Authenticate to include a realm"`, debug(r))
			}
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
			if r.Code != http.StatusUnauthorized {
				t.Error("expected status unauthorized", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_client" {
				t.Error(`expected error to be "invalid_client"`, debug(r))
			}

			if !strings.HasPrefix(r.Header().Get("WWW-Authenticate"), "Basic realm=") {
				t.Error(`expected header WWW-Authenticate to include a realm"`, debug(r))
			}
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
			if r.Code != http.StatusBadRequest {
				t.Error("expected status bad request", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_scope" {
				t.Error(`expected error to be "invalid_scope"`, debug(r))
			}
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
			if r.Code != http.StatusBadRequest {
				t.Error("expected status bad request", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_scope" {
				t.Error(`expected error to be "invalid_scope"`, debug(r))
			}
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

			refreshToken = jsonFieldString(r, "refresh_token")
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
			if r.Code != http.StatusFound {
				t.Error("expected status found", debug(r))
			}

			if fragment(r, "error") != "invalid_scope" {
				t.Error(`expected error to be "invalid_scope"`, debug(r))
			}

			if fragment(r, "state") != "xyz" {
				t.Error(`expected state to be carried over`, debug(r))
			}
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
			if r.Code != http.StatusFound {
				t.Error("expected status found", debug(r))
			}

			if fragment(r, "error") != "invalid_scope" {
				t.Error(`expected error to be "invalid_scope"`, debug(r))
			}

			if fragment(r, "state") != "xyz" {
				t.Error(`expected state to be carried over`, debug(r))
			}
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
			if r.Code != http.StatusFound {
				t.Error("expected status found", debug(r))
			}

			if fragment(r, "error") != "access_denied" {
				t.Error(`expected error to be "access_denied"`, debug(r))
			}

			if fragment(r, "state") != "xyz" {
				t.Error(`expected state to be carried over`, debug(r))
			}
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
			if r.Code != http.StatusFound {
				t.Error("expected status found", debug(r))
			}

			if fragment(r, "error") != "access_denied" {
				t.Error(`expected error to be "access_denied"`, debug(r))
			}

			if fragment(r, "state") != "xyz" {
				t.Error(`expected state to be carried over`, debug(r))
			}
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
			if r.Code != http.StatusFound {
				t.Error("expected status found", debug(r))
			}

			if fragment(r, "token_type") != "bearer" {
				t.Error(`expected token_type to be "bearer"`, debug(r))
			}

			if fragment(r, "scope") != c.ValidScope {
				t.Error(`expected scope to be the valid scope`, debug(r))
			}

			if fragment(r, "expires_in") != strconv.Itoa(c.ExpectedExpiresIn) {
				t.Error(`expected expires_in to be the expected expires in`, debug(r))
			}

			if fragment(r, "state") != "xyz" {
				t.Error(`expected state to be carried over`, debug(r))
			}

			accessToken = fragment(r, "access_token")

			if accessToken == "" {
				t.Error(`expected access_token to be present`, debug(r))
			}
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
			if r.Code != http.StatusFound {
				t.Error("expected status found", debug(r))
			}

			if query(r, "error") != "invalid_scope" {
				t.Error(`expected error to be "invalid_scope"`, debug(r))
			}

			if query(r, "state") != "xyz" {
				t.Error(`expected state to be carried over`, debug(r))
			}
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
			if r.Code != http.StatusFound {
				t.Error("expected status found", debug(r))
			}

			if query(r, "error") != "invalid_scope" {
				t.Error(`expected error to be "invalid_scope"`, debug(r))
			}

			if query(r, "state") != "xyz" {
				t.Error(`expected state to be carried over`, debug(r))
			}
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
			if r.Code != http.StatusFound {
				t.Error("expected status found", debug(r))
			}

			if query(r, "error") != "access_denied" {
				t.Error(`expected error to be "access_denied"`, debug(r))
			}

			if query(r, "state") != "xyz" {
				t.Error(`expected state to be carried over`, debug(r))
			}
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
			if r.Code != http.StatusFound {
				t.Error("expected status found", debug(r))
			}

			if query(r, "error") != "access_denied" {
				t.Error(`expected error to be "access_denied"`, debug(r))
			}

			if query(r, "state") != "xyz" {
				t.Error(`expected state to be carried over`, debug(r))
			}
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
			if r.Code != http.StatusFound {
				t.Error("expected status found", debug(r))
			}

			if query(r, "state") != "xyz" {
				t.Error(`expected state to be carried over`, debug(r))
			}

			authorizationCode = query(r, "code")

			if authorizationCode == "" {
				t.Error(`expected code to be present`, debug(r))
			}
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
			if r.Code != http.StatusUnauthorized {
				t.Error("expected status unauthorized", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_client" {
				t.Error(`expected error to be "invalid_client"`, debug(r))
			}
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
			if r.Code != http.StatusBadRequest {
				t.Error("expected status bad request", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_request" {
				t.Error(`expected error to be "invalid_request"`, debug(r))
			}
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
			if r.Code != http.StatusBadRequest {
				t.Error("expected status bad request", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_grant" {
				t.Error(`expected error to be "invalid_grant"`, debug(r))
			}
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
			if r.Code != http.StatusBadRequest {
				t.Error("expected status bad request", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_grant" {
				t.Error(`expected error to be "invalid_grant"`, debug(r))
			}
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
			if r.Code != http.StatusBadRequest {
				t.Error("expected status bad request", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_grant" {
				t.Error(`expected error to be "invalid_grant"`, debug(r))
			}
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
			if r.Code != http.StatusBadRequest {
				t.Error("expected status bad request", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_grant" {
				t.Error(`expected error to be "invalid_grant"`, debug(r))
			}
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

			refreshToken = jsonFieldString(r, "refresh_token")
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
			if r.Code != http.StatusUnauthorized {
				t.Error("expected status unauthorized", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_client" {
				t.Error(`expected error to be "invalid_client"`, debug(r))
			}
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
			if r.Code != http.StatusBadRequest {
				t.Error("expected status bad request", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_request" {
				t.Error(`expected error to be "invalid_request"`, debug(r))
			}
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
			if r.Code != http.StatusBadRequest {
				t.Error("expected status bad request", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_grant" {
				t.Error(`expected error to be "invalid_grant"`, debug(r))
			}
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
			if r.Code != http.StatusBadRequest {
				t.Error("expected status bad request", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_grant" {
				t.Error(`expected error to be "invalid_grant"`, debug(r))
			}
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
			if r.Code != http.StatusBadRequest {
				t.Error("expected status bad request", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_grant" {
				t.Error(`expected error to be "invalid_grant"`, debug(r))
			}
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
			if r.Code != http.StatusBadRequest {
				t.Error("expected status bad request", debug(r))
			}

			if jsonFieldString(r, "error") != "invalid_scope" {
				t.Error(`expected error to be "invalid_scope"`, debug(r))
			}
		},
	})

	// test refresh token
	RefreshTokenTest(t, c, c.ValidRefreshToken)

	// test refresh token invalidation
	Do(c.Handler, &Request{
		Method:   "POST",
		Path:     c.TokenEndpoint,
		Username: c.ConfidentialClientID,
		Password: c.ConfidentialClientSecret,
		Form: map[string]string{
			"grant_type":    "refresh_token",
			"refresh_token": c.ValidRefreshToken,
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
