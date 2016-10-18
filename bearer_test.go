package oauth2

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewBearerTokenResponse(t *testing.T) {
	res := NewBearerTokenResponse("foo", 1)
	assert.Equal(t, "bearer", res.TokenType)
	assert.Equal(t, "foo", res.AccessToken)
	assert.Equal(t, 1, res.ExpiresIn)
}

func TestParseBearerToken(t *testing.T) {
	req, err := http.NewRequest("GET", "/foo", nil)
	assert.NoError(t, err)

	token, err := ParseBearerToken(req)
	assert.Error(t, err)
	assert.Equal(t, "", token)

	req.Header.Add("Authorization", "Bearer foo")

	token, err = ParseBearerToken(req)
	assert.NoError(t, err)
	assert.Equal(t, "foo", token)
}
