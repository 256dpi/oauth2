package oauth2

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

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
