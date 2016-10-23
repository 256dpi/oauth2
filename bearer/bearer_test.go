package bearer

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewTokenResponse(t *testing.T) {
	res := NewTokenResponse("foo", 1)
	assert.Equal(t, "bearer", res.TokenType)
	assert.Equal(t, "foo", res.AccessToken)
	assert.Equal(t, 1, res.ExpiresIn)
}

func TestParseToken(t *testing.T) {
	req, err := http.NewRequest("GET", "/foo", nil)
	assert.NoError(t, err)

	token, res := ParseToken(req)
	assert.Error(t, res)
	assert.Equal(t, "", token)

	req.Header.Set("Authorization", "foo")

	token, res = ParseToken(req)
	assert.Error(t, res)
	assert.Equal(t, "", token)

	req.Header.Set("Authorization", "Bearer foo")

	token, res = ParseToken(req)
	assert.NoError(t, res)
	assert.Equal(t, "foo", token)
}
