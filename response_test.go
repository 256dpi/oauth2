package oauth2

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewTokenResponse(t *testing.T) {
	r := NewTokenResponse("foo", "bar", 1)
	assert.Equal(t, "foo", r.TokenType)
	assert.Equal(t, "bar", r.AccessToken)
	assert.Equal(t, 1, r.ExpiresIn)
	assert.Equal(t, map[string]string{
		"token_type":   "foo",
		"access_token": "bar",
		"expires_in":   "1",
	}, r.Map())
}

func TestTokenResponseMap(t *testing.T) {
	r := NewTokenResponse("foo", "bar", 1)
	r.RefreshToken = "baz"
	r.Scope = Scope([]string{"qux"})
	r.State = "quuz"

	assert.Equal(t, map[string]string{
		"token_type":    "foo",
		"access_token":  "bar",
		"expires_in":    "1",
		"refresh_token": "baz",
		"scope":         "qux",
		"state":         "quuz",
	}, r.Map())
}

func TestWriteTokenResponse(t *testing.T) {
	w := httptest.NewRecorder()
	r := NewTokenResponse("foo", "bar", 1)

	err := WriteTokenResponse(w, r)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, w.Code)
	assert.JSONEq(t, `{
		"token_type": "foo",
		"access_token": "bar",
		"expires_in": 1
	}`, w.Body.String())
}

func TestRedirectTokenResponse(t *testing.T) {
	w := httptest.NewRecorder()
	r := NewTokenResponse("foo", "bar", 1)
	r = r.SetRedirect("http://example.com", "baz")

	err := WriteTokenResponse(w, r)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t,
		"http://example.com#access_token=bar&expires_in=1&state=baz&token_type=foo",
		w.Header().Get("Location"),
	)
}

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
	r := NewCodeResponse("foo", "http://example.com", "bar")

	err := WriteCodeResponse(w, r)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusFound, w.Code)
	assert.Equal(t, "http://example.com?code=foo&state=bar", w.Header().Get("Location"))
}
