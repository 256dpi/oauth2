package oauth2

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestError(t *testing.T) {
	err := ErrorWithCode(InvalidRequest, "foo").(*Error)
	assert.Error(t, err)
	assert.Equal(t, "invalid_request: foo", err.Error())
	assert.Equal(t, "invalid_request: foo", err.String())
	assert.Equal(t, map[string]string{
		"error":             "invalid_request",
		"error_description": "foo",
	}, err.Map())
}

func TestErrorMap(t *testing.T) {
	err := ErrorWithCode(InvalidRequest, "foo").(*Error)
	err.State = "bar"
	err.URI = "http://example.com"

	assert.Equal(t, map[string]string{
		"error":             "invalid_request",
		"error_description": "foo",
		"error_uri":         "http://example.com",
		"state":             "bar",
	}, err.Map())
}
