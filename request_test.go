package oauth2

import (
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
}
