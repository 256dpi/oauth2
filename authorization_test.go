package oauth2

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseAuthorizationRequestMinimal(t *testing.T) {
	r := newRequest(map[string]string{
		"client_id":     "foo",
		"response_type": TokenResponseType,
		"redirect_uri":  "http://example.com",
	})

	req, err := ParseAuthorizationRequest(r)
	assert.NoError(t, err)
	assert.Equal(t, "token", req.ResponseType)
	assert.Equal(t, Scope(nil), req.Scope)
	assert.Equal(t, "foo", req.ClientID)
	assert.Equal(t, "http://example.com", req.RedirectURI)
	assert.Equal(t, "", req.State)
}

func TestParseAuthorizationRequestFull(t *testing.T) {
	r := newRequest(map[string]string{
		"client_id":     "foo",
		"scope":         "foo bar",
		"response_type": TokenResponseType,
		"redirect_uri":  "http://example.com",
		"state":         "baz",
	})

	req, err := ParseAuthorizationRequest(r)
	assert.NoError(t, err)
	assert.Equal(t, "token", req.ResponseType)
	assert.Equal(t, Scope([]string{"foo", "bar"}), req.Scope)
	assert.Equal(t, "foo", req.ClientID)
	assert.Equal(t, "http://example.com", req.RedirectURI)
	assert.Equal(t, "baz", req.State)
}

func TestParseAuthorizationRequestErrors(t *testing.T) {
	r1, _ := http.NewRequest("PUT", "", nil)
	r2, _ := http.NewRequest("POST", "", nil)

	matrix := []*http.Request{
		r1,
		r2,
		newRequest(nil),
		newRequest(map[string]string{
			"response_type": TokenResponseType,
		}),
		newRequest(map[string]string{
			"response_type": TokenResponseType,
			"client_id":     "foo",
		}),
		newRequest(map[string]string{
			"response_type": TokenResponseType,
			"client_id":     "foo",
			"redirect_uri":  "foo",
		}),
	}

	for _, i := range matrix {
		req, err := ParseAuthorizationRequest(i)
		assert.Nil(t, req)
		assert.Error(t, err)
	}
}
