package hmacsha

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

var testSecret = []byte("abcd1234abcd1234")

func TestToken(t *testing.T) {
	token1, err := Generate(testSecret, 16)
	assert.NoError(t, err)
	assert.NotEmpty(t, token1.Key)
	assert.NotEmpty(t, token1.Signature)
	assert.NotEmpty(t, token1.String())

	token2, err := Parse(testSecret, token1.String())
	assert.NoError(t, err)
	assert.Equal(t, token1.Key, token2.Key)
	assert.Equal(t, token1.Signature, token2.Signature)

	token2, err = Parse(testSecret, token1.String()+"foo")
	assert.Error(t, err)
	assert.Nil(t, token2)
}

func TestParseToken(t *testing.T) {
	token, err := Parse(testSecret, "")
	assert.Error(t, err)
	assert.Nil(t, token)

	token, err = Parse(testSecret, "%.foo")
	assert.Error(t, err)
	assert.Nil(t, token)

	token, err = Parse(testSecret, "foo.%")
	assert.Error(t, err)
	assert.Nil(t, token)
}

func TestGenerate(t *testing.T) {
	token := MustGenerate(testSecret, 16)
	assert.NotNil(t, token)
}

func TestGenerateError(t *testing.T) {
	currentSource := randSource
	randSource = strings.NewReader("")

	token, err := Generate(testSecret, 16)
	assert.Error(t, err)
	assert.Nil(t, token)

	assert.Panics(t, func() {
		MustGenerate(testSecret, 16)
	})

	randSource = currentSource
}
