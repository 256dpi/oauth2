package oauth2

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseTokenRequestMinimal(t *testing.T) {
	r := newRequestWithAuth("foo", "", map[string]string{
		"grant_type": PasswordGrantType,
	})

	req, err := ParseTokenRequest(r)
	assert.NoError(t, err)
	assert.Equal(t, "password", req.GrantType)
	assert.Equal(t, "foo", req.ClientID)
	assert.Equal(t, "", req.ClientSecret)
	assert.Equal(t, Scope(nil), req.Scope)
	assert.Equal(t, "", req.Username)
	assert.Equal(t, "", req.Password)
	assert.Equal(t, "", req.RefreshToken)
	assert.Equal(t, "", req.RedirectURI)
	assert.Equal(t, "", req.Code)
	assert.Equal(t, r, req.HTTP)
}

func TestParseTokenRequestFull(t *testing.T) {
	r := newRequestWithAuth("foo", "bar", map[string]string{
		"grant_type":    PasswordGrantType,
		"scope":         "foo bar",
		"username":      "baz",
		"password":      "qux",
		"refresh_token": "bla",
		"redirect_uri":  "http://example.com",
		"code":          "blaa",
	})

	req, err := ParseTokenRequest(r)
	assert.NoError(t, err)
	assert.Equal(t, "password", req.GrantType)
	assert.Equal(t, "foo", req.ClientID)
	assert.Equal(t, "bar", req.ClientSecret)
	assert.Equal(t, Scope([]string{"foo", "bar"}), req.Scope)
	assert.Equal(t, "baz", req.Username)
	assert.Equal(t, "qux", req.Password)
	assert.Equal(t, "bla", req.RefreshToken)
	assert.Equal(t, "http://example.com", req.RedirectURI)
	assert.Equal(t, "blaa", req.Code)
	assert.Equal(t, r, req.HTTP)
}

func TestParseTokenRequestErrors(t *testing.T) {
	r1, _ := http.NewRequest("GET", "", nil)
	r2, _ := http.NewRequest("POST", "", nil)

	matrix := []struct {
		r *http.Request
		e string
	}{
		{
			r: r1,
			e: "invalid_request: invalid HTTP method",
		},
		{
			r: r2,
			e: "invalid_request: malformed query parameters or body form",
		},
		{
			r: newRequest(nil),
			e: "invalid_request: missing grant type",
		},
		{
			r: newRequest(map[string]string{
				"grant_type": PasswordGrantType,
			}),
			e: "invalid_request: missing or invalid HTTP authorization header",
		},
		{
			r: newRequestWithAuth("foo", "bar", map[string]string{
				"grant_type":   PasswordGrantType,
				"redirect_uri": "blaa%blupp",
			}),
			e: "invalid_request: invalid redirect URI",
		},
		{
			r: newRequestWithAuth("foo", "bar", map[string]string{
				"grant_type":   PasswordGrantType,
				"redirect_uri": "foo",
			}),
			e: "invalid_request: invalid redirect URI",
		},
	}

	for _, i := range matrix {
		req, err := ParseTokenRequest(i.r)
		assert.Nil(t, req)
		assert.Error(t, err)
		assert.Equal(t, i.e, err.Error())
	}
}

func TestParseAuthorizationRequestMinimal(t *testing.T) {
	r := newRequest(map[string]string{
		"client_id":     "foo",
		"response_type": TokenResponseType,
		"redirect_uri":  "http://example.com",
	})

	req, err := ParseAuthorizationRequest(r)
	assert.NoError(t, err)
	assert.Equal(t, "token", req.ResponseType)
	assert.Equal(t, Scope(nil), req.Scope)
	assert.Equal(t, "foo", req.ClientID)
	assert.Equal(t, "http://example.com", req.RedirectURI)
	assert.Equal(t, "", req.State)
	assert.Equal(t, r, req.HTTP)
}

func TestParseAuthorizationRequestFull(t *testing.T) {
	r := newRequest(map[string]string{
		"client_id":     "foo",
		"scope":         "foo bar",
		"response_type": TokenResponseType,
		"redirect_uri":  "http://example.com",
		"state":         "baz",
	})

	req, err := ParseAuthorizationRequest(r)
	assert.NoError(t, err)
	assert.Equal(t, "token", req.ResponseType)
	assert.Equal(t, Scope([]string{"foo", "bar"}), req.Scope)
	assert.Equal(t, "foo", req.ClientID)
	assert.Equal(t, "http://example.com", req.RedirectURI)
	assert.Equal(t, "baz", req.State)
	assert.Equal(t, r, req.HTTP)
}

func TestParseAuthorizationRequestErrors(t *testing.T) {
	r1, _ := http.NewRequest("PUT", "", nil)
	r2, _ := http.NewRequest("POST", "", nil)

	matrix := []*http.Request{
		r1,
		r2,
		newRequest(nil),
		newRequest(map[string]string{
			"response_type": TokenResponseType,
		}),
		newRequest(map[string]string{
			"response_type": TokenResponseType,
			"client_id":     "foo",
		}),
		newRequest(map[string]string{
			"response_type": TokenResponseType,
			"client_id":     "foo",
			"redirect_uri":  "foo",
		}),
	}

	for _, i := range matrix {
		req, err := ParseAuthorizationRequest(i)
		assert.Nil(t, req)
		assert.Error(t, err)
	}
}
