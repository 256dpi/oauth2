package spec

import (
	"net/http"
	"net/http/httptest"
	"testing"
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
			if r.Code != http.StatusOK {
				t.Error("expected status ok", debug(r))
			}
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
			"grant_type":    "refresh_token",
			"refresh_token": refreshToken,
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
		},
	})

	// test access token
	AccessTokenTest(t, c, accessToken)
}
