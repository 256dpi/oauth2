package oauth2

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestClientError(t *testing.T) {
	withServer(func(base string, srv *Server) {
		client := NewClient(ClientConfig{
			BaseURI:       base,
			TokenEndpoint: "/foo",
		})

		// request error
		trs, err := client.Authenticate(TokenRequest{
			GrantType:    ClientCredentialsGrantType,
			ClientID:     "secret",
			ClientSecret: "secret",
		})
		assert.Error(t, err)
		assert.Nil(t, trs)
		assert.Equal(t, "unexpected response: 404 Not Found", err.Error())
	})
}

func TestClientAuthenticate(t *testing.T) {
	withServer(func(base string, srv *Server) {
		client := NewClient(Default(base))

		srv.Clients["c1"] = &ServerEntity{
			Secret:       "secret",
			Confidential: true,
		}

		srv.Users["u1"] = &ServerEntity{
			Secret:       "secret",
			Confidential: true,
		}

		authorizationCode := srv.Config.MustGenerate()

		srv.AuthorizationCodes[authorizationCode.SignatureString()] = &ServerCredential{
			ClientID:  "c1",
			Username:  "ui",
			ExpiresAt: time.Now().Add(time.Hour),
		}

		// unknown client
		trs, err := client.Authenticate(TokenRequest{
			GrantType:    ClientCredentialsGrantType,
			ClientID:     "foo",
			ClientSecret: "secret",
		})
		assert.Equal(t, &Error{
			Name:        "invalid_client",
			Description: "unknown client",
			Status:      http.StatusUnauthorized,
		}, err)
		assert.Nil(t, trs)

		// client credentials
		trs, err = client.Authenticate(TokenRequest{
			GrantType:    ClientCredentialsGrantType,
			ClientID:     "c1",
			ClientSecret: "secret",
		})
		assert.NoError(t, err)
		assert.Equal(t, BearerAccessTokenType, trs.TokenType)
		assert.NotEmpty(t, trs.AccessToken)
		assert.NotEmpty(t, trs.RefreshToken)
		assert.NotZero(t, trs.ExpiresIn)

		// wrong password
		trs, err = client.Authenticate(TokenRequest{
			GrantType:    PasswordGrantType,
			ClientID:     "c1",
			ClientSecret: "secret",
			Username:     "u1",
			Password:     "foo",
		})
		assert.Equal(t, &Error{
			Name:   "access_denied",
			Status: http.StatusForbidden,
		}, err)
		assert.Nil(t, trs)

		// resource owner password
		trs, err = client.Authenticate(TokenRequest{
			GrantType:    PasswordGrantType,
			ClientID:     "c1",
			ClientSecret: "secret",
			Username:     "u1",
			Password:     "secret",
		})
		assert.NoError(t, err)
		assert.Equal(t, BearerAccessTokenType, trs.TokenType)
		assert.NotEmpty(t, trs.AccessToken)
		assert.NotEmpty(t, trs.RefreshToken)
		assert.NotZero(t, trs.ExpiresIn)

		// wrong code
		trs, err = client.Authenticate(TokenRequest{
			GrantType:    AuthorizationCodeGrantType,
			ClientID:     "c1",
			ClientSecret: "secret",
			Code:         "foo",
		})
		assert.Equal(t, &Error{
			Name:        "invalid_request",
			Description: "a token must have two segments separated by a dot",
			Status:      http.StatusBadRequest,
		}, err)
		assert.Nil(t, trs)

		// authorization code
		trs, err = client.Authenticate(TokenRequest{
			GrantType:    AuthorizationCodeGrantType,
			ClientID:     "c1",
			ClientSecret: "secret",
			Code:         authorizationCode.String(),
		})
		assert.NoError(t, err)
		assert.Equal(t, BearerAccessTokenType, trs.TokenType)
		assert.NotEmpty(t, trs.AccessToken)
		assert.NotEmpty(t, trs.RefreshToken)
		assert.NotZero(t, trs.ExpiresIn)
	})
}

func TestClientIntrospect(t *testing.T) {
	withServer(func(base string, srv *Server) {
		client := NewClient(Default(base))

		srv.Clients["c1"] = &ServerEntity{
			Secret:       "secret",
			Confidential: true,
		}

		trs, err := client.Authenticate(TokenRequest{
			GrantType:    ClientCredentialsGrantType,
			ClientID:     "c1",
			ClientSecret: "secret",
		})
		assert.NoError(t, err)

		// invalid token
		irs, err := client.Introspect(IntrospectionRequest{
			Token:        "foo",
			ClientID:     "c1",
			ClientSecret: "secret",
		})
		assert.Equal(t, &Error{
			Name:        "invalid_request",
			Description: "a token must have two segments separated by a dot",
			Status:      http.StatusBadRequest,
		}, err)
		assert.Nil(t, irs)

		// unknown token
		irs, err = client.Introspect(IntrospectionRequest{
			Token:        srv.Config.MustGenerate().String(),
			ClientID:     "c1",
			ClientSecret: "secret",
		})
		assert.NoError(t, err)
		assert.False(t, irs.Active)

		// access token
		irs, err = client.Introspect(IntrospectionRequest{
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
		irs, err = client.Introspect(IntrospectionRequest{
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
	withServer(func(base string, srv *Server) {
		client := NewClient(Default(base))

		srv.Clients["c1"] = &ServerEntity{
			Secret:       "secret",
			Confidential: true,
		}

		trs, err := client.Authenticate(TokenRequest{
			GrantType:    ClientCredentialsGrantType,
			ClientID:     "c1",
			ClientSecret: "secret",
		})
		assert.NoError(t, err)

		// invalid token
		err = client.Revoke(RevocationRequest{
			Token:        "foo",
			ClientID:     "c1",
			ClientSecret: "secret",
		})
		assert.Equal(t, &Error{
			Name:        "invalid_request",
			Description: "a token must have two segments separated by a dot",
			Status:      http.StatusBadRequest,
		}, err)

		// unknown token
		err = client.Revoke(RevocationRequest{
			Token:        srv.Config.MustGenerate().String(),
			ClientID:     "c1",
			ClientSecret: "secret",
		})
		assert.NoError(t, err)

		// access token
		err = client.Revoke(RevocationRequest{
			Token:        trs.AccessToken,
			ClientID:     "c1",
			ClientSecret: "secret",
		})
		assert.NoError(t, err)

		// refresh token
		err = client.Revoke(RevocationRequest{
			Token:        trs.RefreshToken,
			ClientID:     "c1",
			ClientSecret: "secret",
		})
		assert.NoError(t, err)
	})
}
