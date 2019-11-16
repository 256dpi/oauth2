package bearer

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestError(t *testing.T) {
	err := InvalidRequest("foo")
	assert.Error(t, err)
	assert.Equal(t, "invalid_request: foo", err.Error())
}

func TestErrorMap(t *testing.T) {
	err := InvalidRequest("foo")
	err.URI = "http://example.com"
	err.Realm = "bar"
	err.Scope = "baz"

	assert.Equal(t, map[string]string{
		"error":             "invalid_request",
		"error_description": "foo",
		"error_uri":         "http://example.com",
		"realm":             "bar",
		"scope":             "baz",
	}, err.Map())
}

func TestErrorParams(t *testing.T) {
	err := InvalidRequest("foo")
	err.URI = "http://example.com"
	err.Realm = "bar"
	err.Scope = "baz"

	assert.Equal(t, `error="invalid_request", error_description="foo", error_uri="http://example.com", realm="bar", scope="baz"`, err.Params())
}

func TestErrorBuilders(t *testing.T) {
	matrix := []struct {
		err *Error
		cde string
		sta int
	}{
		{ProtectedResource(), "", http.StatusUnauthorized},
		{InvalidRequest("foo"), "invalid_request", http.StatusBadRequest},
		{InvalidToken("foo"), "invalid_token", http.StatusUnauthorized},
		{InsufficientScope("foo"), "insufficient_scope", http.StatusForbidden},
		{ServerError(), "", http.StatusInternalServerError},
	}

	for _, i := range matrix {
		assert.Equal(t, i.sta, i.err.Status, i.err.Name)
		assert.Equal(t, i.cde, i.err.Name, i.err.Name)
	}
}

func TestWriteError(t *testing.T) {
	err1 := InvalidRequest("foo")

	rec := httptest.NewRecorder()

	err2 := WriteError(rec, err1)
	assert.NoError(t, err2)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, `Bearer error="invalid_request", error_description="foo"`, rec.Header().Get("WWW-Authenticate"))
	assert.Empty(t, rec.Body.String())
}

func TestWriteErrorForcedRealm(t *testing.T) {
	err1 := ProtectedResource()

	rec := httptest.NewRecorder()

	err2 := WriteError(rec, err1)
	assert.NoError(t, err2)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, `Bearer realm="OAuth2"`, rec.Header().Get("WWW-Authenticate"))
	assert.Empty(t, rec.Body.String())
}

func TestWriteErrorFallback(t *testing.T) {
	err1 := errors.New("foo")
	rec := httptest.NewRecorder()

	err2 := WriteError(rec, err1)
	assert.NoError(t, err2)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Empty(t, rec.Body.String())
}
