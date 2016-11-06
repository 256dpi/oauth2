package oauth2

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewTokenResponse(t *testing.T) {
	res := NewTokenResponse("foo", "bar", 1)
	assert.Equal(t, "foo", res.TokenType)
	assert.Equal(t, "bar", res.AccessToken)
	assert.Equal(t, 1, res.ExpiresIn)
	assert.Equal(t, map[string]string{
		"token_type":   "foo",
		"access_token": "bar",
		"expires_in":   "1",
	}, res.Map())
}

func TestTokenResponseMap(t *testing.T) {
	res := NewTokenResponse("foo", "bar", 1)
	res.RefreshToken = "baz"
	res.Scope = Scope([]string{"qux"})
	res.State = "quuz"

	assert.Equal(t, map[string]string{
		"token_type":    "foo",
		"access_token":  "bar",
		"expires_in":    "1",
		"refresh_token": "baz",
		"scope":         "qux",
		"state":         "quuz",
	}, res.Map())
}

func TestWriteTokenResponse(t *testing.T) {
	rec := httptest.NewRecorder()
	res := NewTokenResponse("foo", "bar", 1)

	err := WriteTokenResponse(rec, res)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.JSONEq(t, `{
		"token_type": "foo",
		"access_token": "bar",
		"expires_in": 1
	}`, rec.Body.String())
}

func TestRedirectTokenResponse(t *testing.T) {
	rec := httptest.NewRecorder()
	res := NewTokenResponse("foo", "bar", 1)
	res = res.Redirect("http://example.com", "baz", true)

	err := WriteTokenResponse(rec, res)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t,
		"http://example.com#access_token=bar&expires_in=1&state=baz&token_type=foo",
		rec.HeaderMap.Get("Location"),
	)
}

func TestNewCodeResponse(t *testing.T) {
	res := NewCodeResponse("foo", "http://example.com", "bar")
	assert.Equal(t, "foo", res.Code)
	assert.Equal(t, map[string]string{
		"code":  "foo",
		"state": "bar",
	}, res.Map())
}

func TestWriteCodeResponse(t *testing.T) {
	rec := httptest.NewRecorder()
	res := NewCodeResponse("foo", "http://example.com", "bar")

	err := WriteCodeResponse(rec, res)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusFound, rec.Code)
	assert.Equal(t, "http://example.com?code=foo&state=bar", rec.HeaderMap.Get("Location"))
}
