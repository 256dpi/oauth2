package oauth2

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestKnownTokenType(t *testing.T) {
	matrix := []struct {
		gt string
		kn bool
	}{
		{"foo", false},
		{RefreshToken, true},
		{AccessToken, true},
	}

	for _, i := range matrix {
		assert.Equal(t, i.kn, KnownTokenType(i.gt))
	}
}

func TestParseIntrospectionRequestMinimal(t *testing.T) {
	r := newRequestWithAuth("foo", "", map[string]string{
		"token": "foo",
	})

	req, err := ParseIntrospectionRequest(r)
	assert.NoError(t, err)
	assert.Equal(t, "foo", req.Token)
	assert.Equal(t, "", req.TokenTypeHint)
	assert.Equal(t, "foo", req.ClientID)
	assert.Equal(t, "", req.ClientSecret)
}

func TestParseIntrospectionRequestFull(t *testing.T) {
	r := newRequestWithAuth("foo", "bar", map[string]string{
		"token":           "foo",
		"token_type_hint": RefreshToken,
	})

	req, err := ParseIntrospectionRequest(r)
	assert.NoError(t, err)
	assert.Equal(t, "foo", req.Token)
	assert.Equal(t, "refresh_token", req.TokenTypeHint)
	assert.Equal(t, "foo", req.ClientID)
	assert.Equal(t, "bar", req.ClientSecret)
}

func TestParseIntrospectionRequestErrors(t *testing.T) {
	r1, _ := http.NewRequest("GET", "", nil)
	r2, _ := http.NewRequest("POST", "", nil)

	matrix := []struct {
		r *http.Request
		e string
	}{
		{
			r: r1,
			e: "invalid_request: invalid HTTP method",
		},
		{
			r: r2,
			e: "invalid_request: malformed query parameters or body form",
		},
		{
			r: newRequest(nil),
			e: "invalid_request: missing token",
		},
		{
			r: newRequest(map[string]string{
				"token": "foo",
			}),
			e: "invalid_request: missing or invalid HTTP authorization header",
		},
	}

	for _, i := range matrix {
		req, err := ParseIntrospectionRequest(i.r)
		assert.Nil(t, req)
		assert.Error(t, err)
		assert.Equal(t, i.e, err.Error())
	}
}

func TestWriteIntrospectionResponse(t *testing.T) {
	res := NewIntrospectionResponse(true, "foo", "bar", "baz", "quz")

	rec := httptest.NewRecorder()

	err := WriteIntrospectionResponse(rec, res)
	assert.Error(t, err)
	assert.Equal(t, "unknown token type", err.Error())

	res.TokenType = AccessToken

	err = WriteIntrospectionResponse(rec, res)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, http.Header{
		"Cache-Control": {"no-store"},
		"Content-Type":  {"application/json;charset=UTF-8"},
		"Pragma":        {"no-cache"},
	}, rec.Header())
	assert.JSONEq(t, `{
		"active": true,
		"scope": "foo",
		"client_id": "bar",
		"username": "baz",
		"token_type": "access_token"
	}`, rec.Body.String())

	res = &IntrospectionResponse{}

	rec = httptest.NewRecorder()

	err = WriteIntrospectionResponse(rec, res)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, http.Header{
		"Cache-Control": {"no-store"},
		"Content-Type":  {"application/json;charset=UTF-8"},
		"Pragma":        {"no-cache"},
	}, rec.Header())
	assert.JSONEq(t, `{
		"active": false
	}`, rec.Body.String())
}
