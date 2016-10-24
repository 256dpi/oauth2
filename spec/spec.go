// Package spec implements reusable integration tests to test against any OAuth2
// authentication server.
package spec

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
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

	// The scopes that are considered invalid, valid and exceeding by the
	// authentication server.
	InvalidScope   string
	ValidScope     string
	ExceedingScope string

	// The expected "expire_in" value of returned tokens.
	ExpectedExpireIn int

	// The tokens for the protected resource tests.
	InvalidToken      string
	UnknownToken      string
	ExpiredToken      string
	InsufficientToken string

	// The details of the primary resource owner for the password grant test.
	//
	// Note: Only needed if the password grant is supported.
	ResourceOwnerUsername string
	ResourceOwnerPassword string

	// The redirect URI that is considered invalid and valid by the
	// authentication server.
	//
	// Note: Only needed if the implicit grant or authorization code grant is
	// supported.
	InvalidRedirectURI   string
	PrimaryRedirectURI   string
	SecondaryRedirectURI string

	// The invalid, unknown, valid and expired refresh tokens that is used
	// during the refresh token grant tests.
	//
	// Note: Only needed if the refresh token grant is supported.
	InvalidRefreshToken string
	UnknownRefreshToken string
	ValidRefreshToken   string
	ExpiredRefreshToken string

	// The invalid, unknown and expired authorization code that is used during
	// the authorization code grant tests.
	//
	// Note: Only needed if the authorization code grant is supported.
	InvalidAuthorizationCode string
	UnknownAuthorizationCode string
	ExpiredAuthorizationCode string

	// The params needed to authorize the resource owner during the implicit
	// grant or authorization code grant test.
	//
	// Note: Only needed if the implicit grant or authorization code grant
	// is supported.
	AuthorizationParams map[string]string
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
	// validate config
	assert.NotEmpty(t, c.Handler)
	assert.NotEmpty(t, c.TokenEndpoint)
	assert.NotEmpty(t, c.AuthorizeEndpoint)
	assert.NotEmpty(t, c.ProtectedResource)
	assert.NotEmpty(t, c.PrimaryClientID)
	assert.NotEmpty(t, c.PrimaryClientSecret)
	assert.NotEmpty(t, c.SecondaryClientID)
	assert.NotEmpty(t, c.SecondaryClientSecret)
	assert.NotEmpty(t, c.InvalidScope)
	assert.NotEmpty(t, c.ValidScope)
	assert.NotEmpty(t, c.ExceedingScope)
	assert.NotEmpty(t, c.InvalidToken)
	assert.NotEmpty(t, c.UnknownToken)
	assert.NotEmpty(t, c.ExpiredToken)

	t.Run("ProtectedResourceTest", func(t *testing.T) {
		ProtectedResourceTest(t, c)
	})

	if c.PasswordGrantSupport || c.ClientCredentialsGrantSupport ||
		c.AuthorizationCodeGrantSupport || c.RefreshTokenGrantSupport {
		t.Run("TokenEndpointTest", func(t *testing.T) {
			TokenEndpointTest(t, c)
		})
	}

	if c.ImplicitGrantSupport || c.AuthorizationCodeGrantSupport {
		assert.NotEmpty(t, c.InvalidRedirectURI)
		assert.NotEmpty(t, c.PrimaryRedirectURI)
		assert.NotEmpty(t, c.SecondaryRedirectURI)

		t.Run("AuthorizationEndpointTest", func(t *testing.T) {
			AuthorizationEndpointTest(t, c)
		})
	}

	if c.PasswordGrantSupport {
		assert.NotEmpty(t, c.ResourceOwnerUsername)
		assert.NotEmpty(t, c.ResourceOwnerPassword)

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
		assert.NotEmpty(t, c.AuthorizationParams)

		t.Run("ImplicitGrantTest", func(t *testing.T) {
			ImplicitGrantTest(t, c)
		})
	}

	if c.AuthorizationCodeGrantSupport {
		assert.NotEmpty(t, c.AuthorizationParams)
		assert.NotEmpty(t, c.InvalidAuthorizationCode)
		assert.NotEmpty(t, c.UnknownAuthorizationCode)
		assert.NotEmpty(t, c.ExpiredAuthorizationCode)

		t.Run("AuthorizationCodeGrantTest", func(t *testing.T) {
			AuthorizationCodeGrantTest(t, c)
		})
	}

	if c.RefreshTokenGrantSupport {
		assert.NotEmpty(t, c.InvalidRefreshToken)
		assert.NotEmpty(t, c.UnknownRefreshToken)
		assert.NotEmpty(t, c.ValidRefreshToken)
		assert.NotEmpty(t, c.ExpiredRefreshToken)

		t.Run("RefreshTokenGrantTest", func(t *testing.T) {
			RefreshTokenGrantTest(t, c)
		})
	}
}
