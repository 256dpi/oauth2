package client

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/256dpi/oauth2"
)

func TestTokenRequestValues(t *testing.T) {
	tr := oauth2.TokenRequest{}
	assert.Equal(t, url.Values{}, TokenRequestValues(tr))

	tr = oauth2.TokenRequest{
		GrantType:    "password",
		Scope:        oauth2.Scope{"foo", "bar"},
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
	tr1 := oauth2.TokenRequest{
		GrantType:    "password",
		Scope:        oauth2.Scope{"foo", "bar"},
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

	tr2, err := oauth2.ParseTokenRequest(req)
	assert.NoError(t, err)
	assert.Equal(t, tr1, *tr2)
}
