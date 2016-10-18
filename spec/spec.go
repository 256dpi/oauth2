package spec

import (
	"net/http"
	"testing"
)

// A Config declares the configuration of a to be tested OAuth2 authentication
// server.
type Config struct {
	// The server handler.
	Handler http.Handler

	// The token endpoint (e.g. /oauth2/token).
	TokenEndpoint string

	// The authorization endpoint (e.g. /oauth2/authorize).
	AuthorizeEndpoint string

	// The protected resource (e.g. /api/protected).
	ProtectedResource string

	// The to be tested grant flows.
	PasswordGrant          bool
	ClientCredentialsGrant bool
	ImplicitGrant          bool
	AuthorizationCodeGrant bool
	RefreshTokenGrant      bool

	// The details of the client to be used.
	ClientID     string
	ClientSecret string

	// The details of the resource owner to be used.
	OwnerUsername string
	OwnerPassword string

	// The scope that is considered valid by the authentication server.
	ValidScope string

	// The expected "expire_in" value of returned tokens.
	ExpectedExpireIn int

	// The redirect URI that is considered valid by the authentication server.
	ValidRedirectURI string

	// The refresh token that should be used during the refresh token flow tests.
	RefreshToken string

	// The additional params used when authorizing the resource owner during the
	// implicit grant flow test.
	TokenAuthorizationParams map[string]string

	// The additional params used when authorizing the resource owner during the
	// authorization code flow test.
	CodeAuthorizationParams map[string]string
}

// Default returns a common used configuration that can taken as a basis.
func Default(handler http.Handler) *Config {
	return &Config{
		Handler:           handler,
		TokenEndpoint:     "/oauth2/token",
		AuthorizeEndpoint: "/oauth2/authorize",
		ProtectedResource: "/api/protected",
		ExpectedExpireIn:  3600,
	}
}

// Run will run all tests using the specified config.
func Run(t *testing.T, c *Config) {
	t.Run("ProtectedResourceTest", func(t *testing.T) {
		UnauthorizedAccessTest(t, c)
	})

	t.Run("TokenEndpointTest", func(t *testing.T) {
		TokenEndpointTest(t, c)
	})

	t.Run("AuthorizationEndpointTest", func(t *testing.T) {
		AuthorizationEndpointTest(t, c)
	})

	if c.PasswordGrant {
		t.Run("PasswordGrantTest", func(t *testing.T) {
			PasswordGrantTest(t, c)
		})
	}

	if c.ClientCredentialsGrant {
		t.Run("ClientCredentialsGrantTest", func(t *testing.T) {
			ClientCredentialsGrantTest(t, c)
		})
	}

	if c.ImplicitGrant {
		t.Run("ImplicitGrantTest", func(t *testing.T) {
			ImplicitGrantTest(t, c)
		})
	}

	if c.AuthorizationCodeGrant {
		t.Run("AuthorizationCodeGrantTest", func(t *testing.T) {
			AuthorizationCodeGrantTest(t, c)
		})
	}

	if c.RefreshTokenGrant {
		t.Run("RefreshTokenGrantTest", func(t *testing.T) {
			RefreshTokenGrantTest(t, c)
		})
	}
}
