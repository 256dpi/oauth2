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
		{InvalidRequest("foo", "bar"), "invalid_request", http.StatusBadRequest},
		{InvalidClient("foo", "bar"), "invalid_client", http.StatusUnauthorized},
		{InvalidGrant("foo", "bar"), "invalid_grant", http.StatusBadRequest},
		{InvalidScope("foo", "bar"), "invalid_scope", http.StatusBadRequest},
		{UnauthorizedClient("foo", "bar"), "unauthorized_client", http.StatusBadRequest},
		{UnsupportedGrantType("foo", "bar"), "unsupported_grant_type", http.StatusBadRequest},
		{UnsupportedResponseType("foo", "bar"), "unsupported_response_type", http.StatusBadRequest},
		{AccessDenied("foo", "bar"), "access_denied", http.StatusForbidden},
		{ServerError("foo", "bar"), "server_error", http.StatusInternalServerError},
		{TemporarilyUnavailable("foo", "bar"), "temporarily_unavailable", http.StatusServiceUnavailable},
	}

	for _, i := range matrix {
		assert.Equal(t, i.sta, i.err.Status, i.err.Name)
		assert.Equal(t, i.cde, i.err.Name, i.err.Name)
		assert.Equal(t, "foo", i.err.State, i.err.Name)
		assert.Equal(t, "bar", i.err.Description, i.err.Name)
	}
}

func TestError(t *testing.T) {
	err := InvalidRequest("foo", "bar")
	assert.Error(t, err)
	assert.Equal(t, "invalid_request: bar", err.Error())
	assert.Equal(t, "invalid_request: bar", err.String())
	assert.Equal(t, map[string]string{
		"error":             "invalid_request",
		"state":             "foo",
		"error_description": "bar",
	}, err.Map())
}

func TestErrorMap(t *testing.T) {
	err := InvalidRequest("foo", "bar")
	err.URI = "http://example.com"

	assert.Equal(t, map[string]string{
		"error":             "invalid_request",
		"state":             "foo",
		"error_description": "bar",
		"error_uri":         "http://example.com",
	}, err.Map())
}

func TestWriteError(t *testing.T) {
	err1 := InvalidRequest("foo", "bar")
	rec := httptest.NewRecorder()

	err2 := WriteError(rec, err1)
	assert.NoError(t, err2)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.JSONEq(t, `{
		"error": "invalid_request",
		"state":             "foo",
		"error_description": "bar"
	}`, rec.Body.String())
}

func TestWriteErrorRedirect(t *testing.T) {
	err1 := InvalidRequest("foo", "bar")
	rec := httptest.NewRecorder()

	err2 := RedirectError(rec, "http://example.com", false, err1)
	assert.NoError(t, err2)
	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, "http://example.com?error=invalid_request&error_description=bar&state=foo", rec.HeaderMap.Get("Location"))
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

func TestWriteErrorRedirectFallback(t *testing.T) {
	err1 := errors.New("foo")
	rec := httptest.NewRecorder()

	err2 := RedirectError(rec, "http://example.com", false, err1)
	assert.NoError(t, err2)
	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, "http://example.com?error=server_error", rec.HeaderMap.Get("Location"))
}
