package oauth2

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewCodeResponse(t *testing.T) {
	r := NewCodeResponse("foo", "http://example.com", "bar")
	assert.Equal(t, "foo", r.Code)
	assert.Equal(t, map[string]string{
		"code":  "foo",
		"state": "bar",
	}, r.Map())
}

func TestWriteCodeResponse(t *testing.T) {
	w := httptest.NewRecorder()
	r := NewCodeResponse("foo", "http://example.com?foo=bar", "bar")

	err := WriteCodeResponse(w, r)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t, "http://example.com?code=foo&foo=bar&state=bar", w.Header().Get("Location"))
}
