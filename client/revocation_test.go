package client

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/256dpi/oauth2/revocation"
)

func TestRevocationRequestValues(t *testing.T) {
	rr := revocation.Request{}
	assert.Equal(t, url.Values{}, RevocationRequestValues(rr))

	rr = revocation.Request{
		Token:         "token",
		TokenTypeHint: "hint",
		ClientID:      "client-id",
		ClientSecret:  "client-secret",
	}
	assert.Equal(t, url.Values{
		"token":           []string{"token"},
		"token_type_hint": []string{"hint"},
	}, RevocationRequestValues(rr))
}

func TestRevocationRequestBuild(t *testing.T) {
	rr1 := revocation.Request{
		Token:         "token",
		TokenTypeHint: "hint",
		ClientID:      "client-id",
		ClientSecret:  "client-secret",
	}
	req, err := BuildRevocationRequest("http://auth.server/revoke", rr1)
	assert.NoError(t, err)
	assert.Equal(t, "http://auth.server/revoke", req.URL.String())

	rr2, err := revocation.ParseRequest(req)
	assert.NoError(t, err)
	rr2.HTTP = nil
	assert.Equal(t, rr1, *rr2)
}
