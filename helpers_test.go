package oauth2

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWrite(t *testing.T) {
	rec := httptest.NewRecorder()

	err := Write(rec, "foo", http.StatusOK)
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

func TestRedirect(t *testing.T) {
	rec := httptest.NewRecorder()

	err := Redirect(rec, "foo", nil, false)
	assert.Error(t, err)
}

func TestRedirectQuery(t *testing.T) {
	rec := httptest.NewRecorder()

	err := Redirect(rec, "http://example.com?foo=bar", map[string]string{
		"baz": "qux",
	}, false)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, http.Header{
		"Location": []string{
			"http://example.com?baz=qux&foo=bar",
		},
	}, rec.HeaderMap)
}

func TestRedirectFragment(t *testing.T) {
	rec := httptest.NewRecorder()

	err := Redirect(rec, "http://example.com?foo=bar", map[string]string{
		"baz": "qux",
	}, true)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, "", rec.Body.String())
	assert.Equal(t, http.Header{
		"Location": []string{
			"http://example.com?foo=bar#baz=qux",
		},
	}, rec.HeaderMap)
}
