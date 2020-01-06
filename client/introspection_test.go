package client

import (
	"net/url"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/256dpi/oauth2/introspection"
)

func TestIntrospectionRequestValues(t *testing.T) {
	rr := introspection.Request{}
	assert.Equal(t, url.Values{}, IntrospectionRequestValues(rr))

	rr = introspection.Request{
		Token:         "token",
		TokenTypeHint: "hint",
		ClientID:      "client-id",
		ClientSecret:  "client-secret",
	}
	assert.Equal(t, url.Values{
		"token":           []string{"token"},
		"token_type_hint": []string{"hint"},
	}, IntrospectionRequestValues(rr))
}

func TestIntrospectionRequestBuild(t *testing.T) {
	rr1 := introspection.Request{
		Token:         "token",
		TokenTypeHint: "hint",
		ClientID:      "client-id",
		ClientSecret:  "client-secret",
	}
	req, err := BuildIntrospectionRequest("http://auth.server/introspect", rr1)
	assert.NoError(t, err)
	assert.Equal(t, "http://auth.server/introspect", req.URL.String())

	rr2, err := introspection.ParseRequest(req)
	assert.NoError(t, err)
	rr2.HTTP = nil
	assert.Equal(t, rr1, *rr2)
}
