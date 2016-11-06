package bearer

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewTokenResponse(t *testing.T) {
	r := NewTokenResponse("foo", 1)
	assert.Equal(t, "bearer", r.TokenType)
	assert.Equal(t, "foo", r.AccessToken)
	assert.Equal(t, 1, r.ExpiresIn)
}

func TestParseToken(t *testing.T) {
	req, err := http.NewRequest("GET", "/foo", nil)
	assert.NoError(t, err)

	token, err := ParseToken(req)
	assert.Error(t, err)
	assert.Equal(t, "", token)

	req.Header.Set("Authorization", "foo")

	token, err = ParseToken(req)
	assert.Error(t, err)
	assert.Equal(t, "", token)

	req.Header.Set("Authorization", "Bearer foo")

	token, err = ParseToken(req)
	assert.NoError(t, err)
	assert.Equal(t, "foo", token)
}
