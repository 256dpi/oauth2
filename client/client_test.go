package client

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/256dpi/oauth2"
	"github.com/256dpi/oauth2/server"
)

func TestClientError(t *testing.T) {
	withServer(func(base string, srv *server.Server) {
		client := New(Config{
			BaseURI:       base,
			TokenEndpoint: "/foo",
		})

		// request error
		trs, err := client.Authenticate(oauth2.TokenRequest{
			GrantType:    oauth2.ClientCredentialsGrantType,
			ClientID:     "secret",
			ClientSecret: "secret",
		})
		assert.Equal(t, &Error{
			Status: http.StatusNotFound,
			Body:   "404 page not found\n",
		}, err)
		assert.Nil(t, trs)
	})
}

func TestClientAuthenticate(t *testing.T) {
	withServer(func(base string, srv *server.Server) {
		client := New(Default(base))

		srv.Clients["c1"] = &server.Entity{
			Secret:       server.MustHash("secret"),
			Confidential: true,
		}

		srv.Users["u1"] = &server.Entity{
			Secret:       server.MustHash("secret"),
			Confidential: true,
		}

		authorizationCode := srv.Config.MustGenerate()

		srv.AuthorizationCodes[authorizationCode.SignatureString()] = &server.Credential{
			ClientID:  "c1",
			Username:  "ui",
			ExpiresAt: time.Now().Add(time.Hour),
		}

		// unknown client
		trs, err := client.Authenticate(oauth2.TokenRequest{
			GrantType:    oauth2.ClientCredentialsGrantType,
			ClientID:     "foo",
			ClientSecret: "secret",
		})
		assert.Equal(t, &oauth2.Error{
			Name:        "invalid_client",
			Description: "unknown client",
			Status:      http.StatusUnauthorized,
		}, err)
		assert.Nil(t, trs)

		// client credentials
		trs, err = client.Authenticate(oauth2.TokenRequest{
			GrantType:    oauth2.ClientCredentialsGrantType,
			ClientID:     "c1",
			ClientSecret: "secret",
		})
		assert.NoError(t, err)
		assert.Equal(t, oauth2.BearerAccessTokenType, trs.TokenType)
		assert.NotEmpty(t, trs.AccessToken)
		assert.NotEmpty(t, trs.RefreshToken)
		assert.NotZero(t, trs.ExpiresIn)

		// wrong password
		trs, err = client.Authenticate(oauth2.TokenRequest{
			GrantType:    oauth2.PasswordGrantType,
			ClientID:     "c1",
			ClientSecret: "secret",
			Username:     "u1",
			Password:     "foo",
		})
		assert.Equal(t, &oauth2.Error{
			Name:   "access_denied",
			Status: http.StatusForbidden,
		}, err)
		assert.Nil(t, trs)

		// resource owner password
		trs, err = client.Authenticate(oauth2.TokenRequest{
			GrantType:    oauth2.PasswordGrantType,
			ClientID:     "c1",
			ClientSecret: "secret",
			Username:     "u1",
			Password:     "secret",
		})
		assert.NoError(t, err)
		assert.Equal(t, oauth2.BearerAccessTokenType, trs.TokenType)
		assert.NotEmpty(t, trs.AccessToken)
		assert.NotEmpty(t, trs.RefreshToken)
		assert.NotZero(t, trs.ExpiresIn)

		// wrong code
		trs, err = client.Authenticate(oauth2.TokenRequest{
			GrantType:    oauth2.AuthorizationCodeGrantType,
			ClientID:     "c1",
			ClientSecret: "secret",
			Code:         "foo",
		})
		assert.Equal(t, &oauth2.Error{
			Name:        "invalid_request",
			Description: "a token must have two segments separated by a dot",
			Status:      http.StatusBadRequest,
		}, err)
		assert.Nil(t, trs)

		// authorization code
		trs, err = client.Authenticate(oauth2.TokenRequest{
			GrantType:    oauth2.AuthorizationCodeGrantType,
			ClientID:     "c1",
			ClientSecret: "secret",
			Code:         authorizationCode.String(),
		})
		assert.NoError(t, err)
		assert.Equal(t, oauth2.BearerAccessTokenType, trs.TokenType)
		assert.NotEmpty(t, trs.AccessToken)
		assert.NotEmpty(t, trs.RefreshToken)
		assert.NotZero(t, trs.ExpiresIn)
	})
}

func TestClientIntrospect(t *testing.T) {
	withServer(func(base string, srv *server.Server) {
		client := New(Default(base))

		srv.Clients["c1"] = &server.Entity{
			Secret:       server.MustHash("secret"),
			Confidential: true,
		}

		trs, err := client.Authenticate(oauth2.TokenRequest{
			GrantType:    oauth2.ClientCredentialsGrantType,
			ClientID:     "c1",
			ClientSecret: "secret",
		})
		assert.NoError(t, err)

		// invalid token
		irs, err := client.Introspect(oauth2.IntrospectionRequest{
			Token:        "foo",
			ClientID:     "c1",
			ClientSecret: "secret",
		})
		assert.Equal(t, &oauth2.Error{
			Name:        "invalid_request",
			Description: "a token must have two segments separated by a dot",
			Status:      http.StatusBadRequest,
		}, err)
		assert.Nil(t, irs)

		// unknown token
		irs, err = client.Introspect(oauth2.IntrospectionRequest{
			Token:        srv.Config.MustGenerate().String(),
			ClientID:     "c1",
			ClientSecret: "secret",
		})
		assert.NoError(t, err)
		assert.False(t, irs.Active)

		// access token
		irs, err = client.Introspect(oauth2.IntrospectionRequest{
			Token:        trs.AccessToken,
			ClientID:     "c1",
			ClientSecret: "secret",
		})
		assert.NoError(t, err)
		assert.True(t, irs.Active)
		assert.Equal(t, "c1", irs.ClientID)
		assert.Equal(t, "access_token", irs.TokenType)
		assert.NotZero(t, irs.ExpiresAt)

		// refresh token
		irs, err = client.Introspect(oauth2.IntrospectionRequest{
			Token:        trs.RefreshToken,
			ClientID:     "c1",
			ClientSecret: "secret",
		})
		assert.NoError(t, err)
		assert.True(t, irs.Active)
		assert.Equal(t, "c1", irs.ClientID)
		assert.Equal(t, "refresh_token", irs.TokenType)
		assert.NotZero(t, irs.ExpiresAt)
	})
}

func TestClientRevoke(t *testing.T) {
	withServer(func(base string, srv *server.Server) {
		client := New(Default(base))

		srv.Clients["c1"] = &server.Entity{
			Secret:       server.MustHash("secret"),
			Confidential: true,
		}

		trs, err := client.Authenticate(oauth2.TokenRequest{
			GrantType:    oauth2.ClientCredentialsGrantType,
			ClientID:     "c1",
			ClientSecret: "secret",
		})
		assert.NoError(t, err)

		// invalid token
		err = client.Revoke(oauth2.RevocationRequest{
			Token:        "foo",
			ClientID:     "c1",
			ClientSecret: "secret",
		})
		assert.Equal(t, &oauth2.Error{
			Name:        "invalid_request",
			Description: "a token must have two segments separated by a dot",
			Status:      http.StatusBadRequest,
		}, err)

		// unknown token
		err = client.Revoke(oauth2.RevocationRequest{
			Token:        srv.Config.MustGenerate().String(),
			ClientID:     "c1",
			ClientSecret: "secret",
		})
		assert.NoError(t, err)

		// access token
		err = client.Revoke(oauth2.RevocationRequest{
			Token:        trs.AccessToken,
			ClientID:     "c1",
			ClientSecret: "secret",
		})
		assert.NoError(t, err)

		// refresh token
		err = client.Revoke(oauth2.RevocationRequest{
			Token:        trs.RefreshToken,
			ClientID:     "c1",
			ClientSecret: "secret",
		})
		assert.NoError(t, err)
	})
}
