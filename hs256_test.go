package oauth2

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testSecret = []byte("secret")

func TestHS256Token(t *testing.T) {
	token1, err := GenerateHS256Token(testSecret, 16)
	assert.NoError(t, err)
	assert.NotEmpty(t, token1.Key)
	assert.NotEmpty(t, token1.Signature)
	assert.NotEmpty(t, token1.String())

	token2, err := ParseHS256Token(testSecret, token1.String())
	assert.NoError(t, err)
	assert.Equal(t, token1.Key, token2.Key)
	assert.Equal(t, token1.Signature, token2.Signature)

	token2, err = ParseHS256Token(testSecret, token1.String()+"foo")
	assert.Error(t, err)
	assert.Nil(t, token2)
}

func TestParseHS256Token(t *testing.T) {
	token, err := ParseHS256Token(testSecret, "")
	assert.Error(t, err)
	assert.Nil(t, token)

	token, err = ParseHS256Token(testSecret, "%.foo")
	assert.Error(t, err)
	assert.Nil(t, token)

	token, err = ParseHS256Token(testSecret, "foo.%")
	assert.Error(t, err)
	assert.Nil(t, token)
}

func TestGenerateHS256Token(t *testing.T) {
	token := MustGenerateHS256Token(testSecret, 16)
	assert.NotNil(t, token)
}

func TestGenerateHS256TokenError(t *testing.T) {
	currentSource := randSource
	randSource = strings.NewReader("")

	token, err := GenerateHS256Token(testSecret, 16)
	assert.Error(t, err)
	assert.Nil(t, token)

	assert.Panics(t, func() {
		MustGenerateHS256Token(testSecret, 16)
	})

	randSource = currentSource
}
