package oauth2

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseAccessTokenRequestMinimal(t *testing.T) {
	r := newRequestWithAuth("foo", "", map[string]string{
		"grant_type": "password",
	})

	req, err := ParseAccessTokenRequest(r)
	assert.NoError(t, err)
	assert.Equal(t, "password", req.GrantType.String())
	assert.Equal(t, "foo", req.ClientID)
	assert.Equal(t, "", req.ClientSecret)
	assert.Equal(t, Scope(nil), req.Scope)
	assert.Equal(t, "", req.Username)
	assert.Equal(t, "", req.Password)
	assert.Equal(t, "", req.RefreshToken)
	assert.Equal(t, "", req.RedirectURI)
	assert.Equal(t, "", req.Code)
	assert.False(t, req.Confidential())
	assert.NoError(t, req.Validate())
}

func TestParseAccessTokenRequestFull(t *testing.T) {
	r := newRequestWithAuth("foo", "bar", map[string]string{
		"grant_type":    "password",
		"scope":         "foo bar",
		"username":      "baz",
		"password":      "qux",
		"refresh_token": "bla",
		"redirect_uri":  "http://example.com",
		"code":          "blaa",
	})

	req, err := ParseAccessTokenRequest(r)
	assert.NoError(t, err)
	assert.Equal(t, "password", req.GrantType.String())
	assert.Equal(t, "foo", req.ClientID)
	assert.Equal(t, "bar", req.ClientSecret)
	assert.Equal(t, Scope([]string{"foo", "bar"}), req.Scope)
	assert.Equal(t, "baz", req.Username)
	assert.Equal(t, "qux", req.Password)
	assert.Equal(t, "bla", req.RefreshToken)
	assert.Equal(t, "http://example.com", req.RedirectURI)
	assert.Equal(t, "blaa", req.Code)
	assert.True(t, req.Confidential())
	assert.NoError(t, req.Validate())
}

func TestParseAccessTokenRequestErrors(t *testing.T) {
	r1, _ := http.NewRequest("GET", "", nil)
	r2, _ := http.NewRequest("POST", "", nil)

	matrix := []*http.Request{
		r1,
		r2,
		newRequest(nil),
		newRequest(map[string]string{
			"grant_type": "password",
		}),
		newRequestWithAuth("foo", "bar", map[string]string{
			"grant_type":   "password",
			"redirect_uri": "blaa%blupp",
		}),
		newRequestWithAuth("foo", "bar", map[string]string{
			"grant_type":   "password",
			"redirect_uri": "foo",
		}),
	}

	for _, i := range matrix {
		req, err := ParseAccessTokenRequest(i)
		assert.Nil(t, req)
		assert.Error(t, err)
	}
}

func TestAccessTokenRequestValidate(t *testing.T) {
	matrix := []*http.Request{
		newRequestWithAuth("foo", "", map[string]string{
			"grant_type": "foo",
			"scope":      "foo",
		}),
	}

	for _, i := range matrix {
		req, err := ParseAccessTokenRequest(i)
		assert.NotNil(t, req)
		assert.NoError(t, err)

		err = req.Validate()
		assert.Error(t, err)
	}
}

func TestParseAuthorizationRequestMinimal(t *testing.T) {
	r := newRequest(map[string]string{
		"client_id":     "foo",
		"response_type": "token",
		"redirect_uri":  "http://example.com",
	})

	req, err := ParseAuthorizationRequest(r)
	assert.NoError(t, err)
	assert.Equal(t, "token", req.ResponseType.String())
	assert.Equal(t, Scope(nil), req.Scope)
	assert.Equal(t, "foo", req.ClientID)
	assert.Equal(t, "http://example.com", req.RedirectURI)
	assert.Equal(t, "", req.State)
	assert.NoError(t, req.Validate())
}

func TestParseAuthorizationRequestFull(t *testing.T) {
	r := newRequest(map[string]string{
		"client_id":     "foo",
		"scope":         "foo bar",
		"response_type": "token",
		"redirect_uri":  "http://example.com",
		"state":         "baz",
	})

	req, err := ParseAuthorizationRequest(r)
	assert.NoError(t, err)
	assert.Equal(t, "token", req.ResponseType.String())
	assert.Equal(t, Scope([]string{"foo", "bar"}), req.Scope)
	assert.Equal(t, "foo", req.ClientID)
	assert.Equal(t, "http://example.com", req.RedirectURI)
	assert.Equal(t, "baz", req.State)
	assert.NoError(t, req.Validate())
}

func TestParseAuthorizationRequestErrors(t *testing.T) {
	r1, _ := http.NewRequest("PUT", "", nil)
	r2, _ := http.NewRequest("POST", "", nil)

	matrix := []*http.Request{
		r1,
		r2,
		newRequest(nil),
		newRequest(map[string]string{
			"response_type": "token",
		}),
		newRequest(map[string]string{
			"response_type": "token",
			"client_id":     "foo",
		}),
		newRequest(map[string]string{
			"response_type": "token",
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

func TestAuthorizationRequestValidate(t *testing.T) {
	matrix := []*http.Request{
		newRequest(map[string]string{
			"response_type": "foo",
			"scope":         "foo",
			"client_id":     "foo",
			"redirect_uri":  "http://example.com",
		}),
	}

	for _, i := range matrix {
		req, err := ParseAuthorizationRequest(i)
		assert.NotNil(t, req)
		assert.NoError(t, err)

		err = req.Validate()
		assert.Error(t, err)
	}
}
