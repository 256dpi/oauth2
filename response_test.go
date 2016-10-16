package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewTokenResponse(t *testing.T) {
	res := NewTokenResponse("foo", "bar", 1)
	assert.Equal(t, "foo", res.TokenType)
	assert.Equal(t, "bar", res.AccessToken)
	assert.Equal(t, 1, res.ExpiresIn)
	assert.Equal(t, map[string]string{
		"token_type":   "foo",
		"access_token": "bar",
		"expires_in":   "1",
	}, res.Map())
}

func TestTokenResponseMap(t *testing.T) {
	res := NewTokenResponse("foo", "bar", 1)
	res.RefreshToken = "baz"
	res.Scope = Scope([]string{"qux"})
	res.State = "quuz"
	res.ExtraFields = map[string]string{
		"bla": "blup",
	}

	assert.Equal(t, map[string]string{
		"token_type":    "foo",
		"access_token":  "bar",
		"expires_in":    "1",
		"refresh_token": "baz",
		"scope":         "qux",
		"state":         "quuz",
		"bla":           "blup",
	}, res.Map())
}

func TestNewAuthorizationCodeResponse(t *testing.T) {
	res := NewAuthorizationCodeResponse("foo")
	assert.Equal(t, "foo", res.Code)
	assert.Equal(t, map[string]string{
		"code": "foo",
	}, res.Map())
}

func TestAuthorizationCodeResponseMap(t *testing.T) {
	res := NewAuthorizationCodeResponse("foo")
	res.State = "bar"
	res.ExtraFields = map[string]string{
		"bla": "blup",
	}

	assert.Equal(t, map[string]string{
		"code":  "foo",
		"state": "bar",
		"bla":   "blup",
	}, res.Map())
}
