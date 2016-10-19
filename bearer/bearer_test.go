package bearer

import (
	"net/http"
	"testing"

	"errors"
	"github.com/stretchr/testify/assert"
	"net/http/httptest"
)

func TestNewTokenResponse(t *testing.T) {
	res := NewTokenResponse("foo", 1)
	assert.Equal(t, "bearer", res.TokenType)
	assert.Equal(t, "foo", res.AccessToken)
	assert.Equal(t, 1, res.ExpiresIn)
}

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
	}

	for _, i := range matrix {
		assert.Equal(t, i.sta, i.err.Status, i.err.Name)
		assert.Equal(t, i.cde, i.err.Name, i.err.Name)
	}
}

func TestParseToken(t *testing.T) {
	req, err := http.NewRequest("GET", "/foo", nil)
	assert.NoError(t, err)

	token, res := ParseToken(req)
	assert.Error(t, res)
	assert.Equal(t, "", token)

	req.Header.Set("Authorization", "foo")

	token, res = ParseToken(req)
	assert.Error(t, res)
	assert.Equal(t, "", token)

	req.Header.Set("Authorization", "Bearer foo")

	token, res = ParseToken(req)
	assert.NoError(t, res)
	assert.Equal(t, "foo", token)
}

func TestWriteError(t *testing.T) {
	err1 := InvalidRequest("foo")

	rec := httptest.NewRecorder()

	err2 := WriteError(rec, err1)
	assert.NoError(t, err2)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, `Bearer error="invalid_request", error_description="foo"`, rec.HeaderMap.Get("WWW-Authenticate"))
	assert.Empty(t, rec.Body.String())
}

func TestWriteErrorForcedRealm(t *testing.T) {
	err1 := ProtectedResource()

	rec := httptest.NewRecorder()

	err2 := WriteError(rec, err1)
	assert.NoError(t, err2)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, `Bearer realm="OAuth2"`, rec.HeaderMap.Get("WWW-Authenticate"))
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
