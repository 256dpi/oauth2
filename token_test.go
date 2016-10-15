package oauth2

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestToken(t *testing.T) {
	token1, err := GenerateToken(testSecret, 16)
	assert.NoError(t, err)
	assert.NotEmpty(t, token1.Key)
	assert.NotEmpty(t, token1.Signature)
	assert.NotEmpty(t, token1.String())

	token2, err := ParseToken(testSecret, token1.String())
	assert.NoError(t, err)
	assert.Equal(t, token1.Key, token2.Key)
	assert.Equal(t, token1.Signature, token2.Signature)

	token2, err = ParseToken(testSecret, token1.String()+"foo")
	assert.Error(t, err)
	assert.Nil(t, token2)
}

func TestParseToken(t *testing.T) {
	token, err := ParseToken(testSecret, "")
	assert.Error(t, err)
	assert.Nil(t, token)

	token, err = ParseToken(testSecret, "%.foo")
	assert.Error(t, err)
	assert.Nil(t, token)

	token, err = ParseToken(testSecret, "foo.%")
	assert.Error(t, err)
	assert.Nil(t, token)
}

func TestGenerateToken(t *testing.T) {
	currentSource := randSource
	randSource = strings.NewReader("")

	token, err := GenerateToken(testSecret, 16)
	assert.Error(t, err)
	assert.Nil(t, token)

	randSource = currentSource
}
