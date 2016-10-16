package oauth2

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewBearerTokenResponse(t *testing.T) {
	res := NewBearerTokenResponse("foo", 10)
	assert.Equal(t, Bearer, res.TokenType)
	assert.Equal(t, "foo", res.AccessToken)
	assert.Equal(t, 10, res.ExpiresIn)
}

func TestParseBearerToken(t *testing.T) {
	token1, err := GenerateToken(testSecret, 16)
	assert.NoError(t, err)

	req, err := http.NewRequest("GET", "/foo", nil)
	assert.NoError(t, err)

	token2, err := ParseBearerToken(testSecret, req)
	assert.Error(t, err)
	assert.Nil(t, token2)

	req.Header.Add("Authorization", "Bearer "+token1.String())

	token2, err = ParseBearerToken(testSecret, req)
	assert.NoError(t, err)
	assert.NotNil(t, token2)
}
