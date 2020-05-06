package oauth2

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseTokenRequestMinimal(t *testing.T) {
	r := newRequestWithAuth("foo", "", map[string]string{
		"grant_type": PasswordGrantType,
	})

	req, err := ParseTokenRequest(r)
	assert.NoError(t, err)
	assert.Equal(t, "password", req.GrantType)
	assert.Equal(t, "foo", req.ClientID)
	assert.Equal(t, "", req.ClientSecret)
	assert.Equal(t, Scope(nil), req.Scope)
	assert.Equal(t, "", req.Username)
	assert.Equal(t, "", req.Password)
	assert.Equal(t, "", req.RefreshToken)
	assert.Equal(t, "", req.RedirectURI)
	assert.Equal(t, "", req.Code)
}

func TestParseTokenRequestFull(t *testing.T) {
	r := newRequestWithAuth("foo", "bar", map[string]string{
		"grant_type":    PasswordGrantType,
		"scope":         "foo bar",
		"username":      "baz",
		"password":      "qux",
		"refresh_token": "bla",
		"redirect_uri":  "http://example.com",
		"code":          "blaa",
	})

	req, err := ParseTokenRequest(r)
	assert.NoError(t, err)
	assert.Equal(t, "password", req.GrantType)
	assert.Equal(t, "foo", req.ClientID)
	assert.Equal(t, "bar", req.ClientSecret)
	assert.Equal(t, Scope{"foo", "bar"}, req.Scope)
	assert.Equal(t, "baz", req.Username)
	assert.Equal(t, "qux", req.Password)
	assert.Equal(t, "bla", req.RefreshToken)
	assert.Equal(t, "http://example.com", req.RedirectURI)
	assert.Equal(t, "blaa", req.Code)
}

func TestParseTokenRequestErrors(t *testing.T) {
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
			e: "invalid_request: missing grant type",
		},
		{
			r: newRequest(map[string]string{
				"grant_type": PasswordGrantType,
			}),
			e: "invalid_request: missing or invalid HTTP authorization header",
		},
		{
			r: newRequestWithAuth("foo", "bar", map[string]string{
				"grant_type":   PasswordGrantType,
				"redirect_uri": "blaa%blupp",
			}),
			e: "invalid_request: invalid redirect URI",
		},
		{
			r: newRequestWithAuth("foo", "bar", map[string]string{
				"grant_type":   PasswordGrantType,
				"redirect_uri": "foo",
			}),
			e: "invalid_request: invalid redirect URI",
		},
	}

	for _, i := range matrix {
		req, err := ParseTokenRequest(i.r)
		assert.Nil(t, req)
		assert.Error(t, err)
		assert.Equal(t, i.e, err.Error())
	}
}

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
	r.Scope = Scope{"qux"}
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
	r = r.SetRedirect("http://example.com?foo=bar", "baz")

	err := WriteTokenResponse(w, r)
	assert.NoError(t, err)
	assert.Equal(t, http.StatusSeeOther, w.Code)
	assert.Equal(t,
		"http://example.com?foo=bar#access_token=bar&expires_in=1&state=baz&token_type=foo",
		w.Header().Get("Location"),
	)
}

func TestTokenRequestValues(t *testing.T) {
	tr := TokenRequest{}
	assert.Equal(t, url.Values{}, TokenRequestValues(tr))

	tr = TokenRequest{
		GrantType:    "password",
		Scope:        Scope{"foo", "bar"},
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Username:     "username",
		Password:     "password",
		RefreshToken: "refresh-token",
		RedirectURI:  "http://redirect.uri",
		Code:         "code",
	}
	assert.Equal(t, url.Values{
		"grant_type":    []string{"password"},
		"scope":         []string{"foo bar"},
		"username":      []string{"username"},
		"password":      []string{"password"},
		"refresh_token": []string{"refresh-token"},
		"redirect_uri":  []string{"http%3A%2F%2Fredirect.uri"},
		"code":          []string{"code"},
	}, TokenRequestValues(tr))
}

func TestTokenRequestBuild(t *testing.T) {
	tr1 := TokenRequest{
		GrantType:    "password",
		Scope:        Scope{"foo", "bar"},
		ClientID:     "client-id",
		ClientSecret: "client-secret",
		Username:     "username",
		Password:     "password",
		RefreshToken: "refresh-token",
		RedirectURI:  "http://redirect.uri",
		Code:         "code",
	}
	req, err := BuildTokenRequest("http://auth.server/token", tr1)
	assert.NoError(t, err)
	assert.Equal(t, "http://auth.server/token", req.URL.String())

	tr2, err := ParseTokenRequest(req)
	assert.NoError(t, err)
	assert.Equal(t, tr1, *tr2)
}
