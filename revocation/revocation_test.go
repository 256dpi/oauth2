package revocation

import (
	"net/http"
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

func TestParseRequestMinimal(t *testing.T) {
	r := newRequestWithAuth("foo", "", map[string]string{
		"token": "foo",
	})

	req, err := ParseRequest(r)
	assert.NoError(t, err)
	assert.Equal(t, "foo", req.Token)
	assert.Equal(t, "", req.TokenTypeHint)
	assert.Equal(t, "foo", req.ClientID)
	assert.Equal(t, "", req.ClientSecret)
	assert.Equal(t, r, req.HTTP)
}

func TestParseRequestFull(t *testing.T) {
	r := newRequestWithAuth("foo", "bar", map[string]string{
		"token":           "foo",
		"token_type_hint": RefreshToken,
	})

	req, err := ParseRequest(r)
	assert.NoError(t, err)
	assert.Equal(t, "foo", req.Token)
	assert.Equal(t, "refresh_token", req.TokenTypeHint)
	assert.Equal(t, "foo", req.ClientID)
	assert.Equal(t, "bar", req.ClientSecret)
	assert.Equal(t, r, req.HTTP)
}

func TestParseRequestErrors(t *testing.T) {
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
		req, err := ParseRequest(i.r)
		assert.Nil(t, req)
		assert.Error(t, err)
		assert.Equal(t, i.e, err.Error())
	}
}

func TestUnsupportedTokenType(t *testing.T) {
	i := UnsupportedTokenType("foo")

	assert.Equal(t, "unsupported_token_type", i.Name)
	assert.Equal(t, http.StatusBadRequest, i.Status)
	assert.Equal(t, "", i.State)
	assert.Equal(t, "foo", i.Description)
}
