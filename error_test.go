package oauth2

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrorBuilders(t *testing.T) {
	matrix := []struct {
		err *Error
		cde string
		sta int
	}{
		{InvalidRequest("foo"), "invalid_request", http.StatusBadRequest},
		{InvalidClient("foo"), "invalid_client", http.StatusUnauthorized},
		{InvalidGrant("foo"), "invalid_grant", http.StatusBadRequest},
		{InvalidScope("foo"), "invalid_scope", http.StatusBadRequest},
		{UnauthorizedClient("foo"), "unauthorized_client", http.StatusBadRequest},
		{UnsupportedGrantType("foo"), "unsupported_grant_type", http.StatusBadRequest},
		{UnsupportedResponseType("foo"), "unsupported_response_type", http.StatusBadRequest},
		{AccessDenied("foo"), "access_denied", http.StatusForbidden},
		{ServerError("foo"), "server_error", http.StatusInternalServerError},
		{TemporarilyUnavailable("foo"), "temporarily_unavailable", http.StatusServiceUnavailable},
	}

	for _, i := range matrix {
		assert.Equal(t, i.sta, i.err.Status, i.err.Name)
		assert.Equal(t, i.cde, i.err.Name, i.err.Name)
		assert.Equal(t, "foo", i.err.Description, i.err.Name)
	}
}

func TestError(t *testing.T) {
	err := InvalidRequest("foo")
	assert.Error(t, err)
	assert.Equal(t, "invalid_request: foo", err.Error())
	assert.Equal(t, "invalid_request: foo", err.String())
	assert.Equal(t, map[string]string{
		"error":             "invalid_request",
		"error_description": "foo",
	}, err.Map())
}

func TestErrorMap(t *testing.T) {
	err := InvalidRequest("foo")
	err.URI = "http://example.com"

	assert.Equal(t, map[string]string{
		"error":             "invalid_request",
		"error_description": "foo",
		"error_uri":         "http://example.com",
	}, err.Map())
}

func TestWriteError(t *testing.T) {
	err1 := InvalidRequest("foo")
	err1.Headers = map[string]string{
		"foo": "bar",
	}

	rec := httptest.NewRecorder()

	err2 := WriteError(rec, err1)
	assert.NoError(t, err2)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, "bar", rec.Header().Get("foo"))
	assert.JSONEq(t, `{
		"error": "invalid_request",
		"error_description": "foo"
	}`, rec.Body.String())
}

func TestWriteErrorAsRedirect(t *testing.T) {
	err1 := InvalidRequest("foo").SetRedirect("http://example.com", "bar", false)
	rec := httptest.NewRecorder()

	err2 := WriteError(rec, err1)
	assert.NoError(t, err2)
	assert.Equal(t, http.StatusSeeOther, rec.Code)
	assert.Equal(t, "http://example.com?error=invalid_request&error_description=foo&state=bar", rec.Header().Get("Location"))
}

func TestWriteErrorFallback(t *testing.T) {
	err1 := errors.New("foo")
	rec := httptest.NewRecorder()

	err2 := WriteError(rec, err1)
	assert.NoError(t, err2)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.JSONEq(t, `{
		"error": "server_error"
	}`, rec.Body.String())
}
