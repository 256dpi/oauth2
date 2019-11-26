package introspection

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestWriteResponse(t *testing.T) {
	res := NewResponse(true, "foo", "bar", "baz", "quz")

	rec := httptest.NewRecorder()

	err := WriteResponse(rec, res)
	assert.Error(t, err)
	assert.Equal(t, "unknown token type", err.Error())

	res.TokenType = AccessToken

	err = WriteResponse(rec, res)
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

	res = &Response{}

	rec = httptest.NewRecorder()

	err = WriteResponse(rec, res)
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
