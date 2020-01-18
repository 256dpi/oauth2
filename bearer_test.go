package oauth2

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewBearerTokenResponse(t *testing.T) {
	r := NewBearerTokenResponse("foo", 1)
	assert.Equal(t, "bearer", r.TokenType)
	assert.Equal(t, "foo", r.AccessToken)
	assert.Equal(t, 1, r.ExpiresIn)
}

func TestParseBearerToken(t *testing.T) {
	req, err := http.NewRequest("GET", "/foo", nil)
	assert.NoError(t, err)

	token, err := ParseBearerToken(req)
	assert.Error(t, err)
	assert.Equal(t, "", token)

	req.Header.Set("Authorization", "foo")

	token, err = ParseBearerToken(req)
	assert.Error(t, err)
	assert.Equal(t, "", token)

	req.Header.Set("Authorization", "Bearer foo")

	token, err = ParseBearerToken(req)
	assert.NoError(t, err)
	assert.Equal(t, "foo", token)
}

func TestWriteBearerError(t *testing.T) {
	err1 := InvalidRequest("foo")

	rec := httptest.NewRecorder()

	err2 := WriteBearerError(rec, err1)
	assert.NoError(t, err2)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Equal(t, `Bearer error="invalid_request", error_description="foo"`, rec.Header().Get("WWW-Authenticate"))
	assert.Empty(t, rec.Body.String())
}

func TestWriteBearerErrorForcedRealm(t *testing.T) {
	err1 := ProtectedResource()

	rec := httptest.NewRecorder()

	err2 := WriteBearerError(rec, err1)
	assert.NoError(t, err2)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
	assert.Equal(t, `Bearer realm="OAuth2"`, rec.Header().Get("WWW-Authenticate"))
	assert.Empty(t, rec.Body.String())
}

func TestWriteBearerErrorFallback(t *testing.T) {
	err1 := errors.New("foo")
	rec := httptest.NewRecorder()

	err2 := WriteBearerError(rec, err1)
	assert.NoError(t, err2)
	assert.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Empty(t, rec.Body.String())
}
