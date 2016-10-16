package oauth2

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWriteJSON(t *testing.T) {
	rec := httptest.NewRecorder()

	err := WriteJSON(rec, "foo", http.StatusOK)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, http.Header{
		"Content-Type": []string{
			"application/json;charset=UTF-8",
		},
		"Cache-Control": []string{
			"no-store",
		},
		"Pragma": []string{
			"no-cache",
		},
	}, rec.HeaderMap)
}

func TestWriteRedirect(t *testing.T) {
	rec := httptest.NewRecorder()

	err := WriteRedirect(rec, "http://example.com", map[string]string{
		"foo": "bar",
	}, map[string]string{
		"baz": "qux",
	})
	assert.NoError(t, err)
	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, http.Header{
		"Location": []string{
			"http://example.com?foo=bar#baz=qux",
		},
	}, rec.HeaderMap)
}

func TestWriteRedirectError(t *testing.T) {
	rec := httptest.NewRecorder()

	err := WriteRedirect(rec, "%", nil, nil)
	assert.Error(t, err)
}
