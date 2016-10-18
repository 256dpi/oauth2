// Package spec implements reusable integration tests to test any OAuth2
// authentication server.
package spec

import (
	"net/http"
	"testing"
)

// A Config declares the needed info for testing an OAuth2 authentication server.
type Config struct {
	// The server handler.
	Handler http.Handler

	// The token endpoint (e.g. /oauth2/token).
	TokenEndpoint string

	// The authorization endpoint (e.g. /oauth2/authorize).
	AuthorizeEndpoint string

	// The protected resource (e.g. /api/protected).
	ProtectedResource string

	// The supported grants.
	PasswordGrantSupport          bool
	ClientCredentialsGrantSupport bool
	ImplicitGrantSupport          bool
	AuthorizationCodeGrantSupport bool
	RefreshTokenGrantSupport      bool

	// The details of the primary client for grant tests.
	PrimaryClientID     string
	PrimaryClientSecret string

	// The details of the secondary client for security tests.
	SecondaryClientID     string
	SecondaryClientSecret string

	// The details of the primary resource owner for grant tests.
	PrimaryResourceOwnerUsername string
	PrimaryResourceOwnerPassword string

	// The details of the secondary resource owner for security tests.
	SecondaryResourceOwnerUsername string
	SecondaryResourceOwnerPassword string

	// The scopes that are considered invalid, valid and exceeding by the
	// authentication server.
	InvalidScope   string
	ValidScope     string
	ExceedingScope string

	// The expected "expire_in" value of returned tokens.
	ExpectedExpireIn int

	// The redirect URI that is considered invalid and valid by the
	// authentication server.
	InvalidRedirectURI string
	ValidRedirectURI   string

	// The invalid and valid refresh token that should be used during the
	// refresh token grant tests.
	InvalidRefreshToken string
	ValidRefreshToken   string

	// The params needed to authorize the resource owner during the implicit
	// grant test.
	TokenAuthorizationParams map[string]string

	// The params needed to authorize the resource owner during the authorization
	// code grant test.
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

	if c.PasswordGrantSupport {
		t.Run("PasswordGrantTest", func(t *testing.T) {
			PasswordGrantTest(t, c)
		})
	}

	if c.ClientCredentialsGrantSupport {
		t.Run("ClientCredentialsGrantTest", func(t *testing.T) {
			ClientCredentialsGrantTest(t, c)
		})
	}

	if c.ImplicitGrantSupport {
		t.Run("ImplicitGrantTest", func(t *testing.T) {
			ImplicitGrantTest(t, c)
		})
	}

	if c.AuthorizationCodeGrantSupport {
		t.Run("AuthorizationCodeGrantTest", func(t *testing.T) {
			AuthorizationCodeGrantTest(t, c)
		})
	}

	if c.RefreshTokenGrantSupport {
		t.Run("RefreshTokenGrantTest", func(t *testing.T) {
			RefreshTokenGrantTest(t, c)
		})
	}
}
