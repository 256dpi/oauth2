// Package spec implements reusable integration tests to test against any OAuth2
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

	// The revocation endpoint (e.g. /oauth2/revoke).
	RevocationEndpoint string

	// The protected resource (e.g. /api/protected).
	ProtectedResource string

	// The supported grants.
	PasswordGrantSupport          bool
	ClientCredentialsGrantSupport bool
	ImplicitGrantSupport          bool
	AuthorizationCodeGrantSupport bool
	RefreshTokenGrantSupport      bool

	// The details of a confidential client.
	ConfidentialClientID     string
	ConfidentialClientSecret string

	// The details of a public client.
	PublicClientID string

	// The scopes that are considered invalid, valid and exceeding by the
	// authentication server.
	InvalidScope   string
	ValidScope     string
	ExceedingScope string

	// The expected "expire_in" value of returned tokens.
	ExpectedExpiresIn int

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

	// The params and headers needed to authorize the resource owner during the
	// implicit grant or authorization code grant test.
	//
	// Note: Only needed if the implicit grant or authorization code grant
	// is supported.
	InvalidAuthorizationParams  map[string]string
	InvalidAuthorizationHeaders map[string]string
	ValidAuthorizationParams    map[string]string
	ValidAuthorizationHeaders   map[string]string

	// If enabled the implementation is checked for properly revoking tokens
	// if a code replay attack is carried out.
	CodeReplayMitigation bool
}

// Default returns a common used configuration that can taken as a basis.
func Default(handler http.Handler) *Config {
	return &Config{
		Handler:             handler,
		TokenEndpoint:       "/oauth2/token",
		AuthorizeEndpoint:   "/oauth2/authorize",
		RevocationEndpoint:  "/oauth2/revoke",
		ProtectedResource:   "/api/protected",
		ExpectedExpiresIn:   3600,
		InvalidToken:        "invalid",
		InvalidRedirectURI:  "http://invalid.com",
		InvalidRefreshToken: "invalid",
	}
}

// Run will run all tests using the specified config.
func Run(t *testing.T, c *Config) {
	// validate config
	assert(t, c.Handler != nil, "setting Handler is required")
	assert(t, c.TokenEndpoint != "", "setting TokenEndpoint is required")
	assert(t, c.AuthorizeEndpoint != "", "setting AuthorizeEndpoint is required")
	assert(t, c.ProtectedResource != "", "setting ProtectedResource is required")
	assert(t, c.ConfidentialClientID != "", "setting ConfidentialClientID is required")
	assert(t, c.ConfidentialClientSecret != "", "setting ConfidentialClientSecret is required")
	assert(t, c.PublicClientID != "", "setting PublicClientID is required")
	assert(t, c.InvalidScope != "", "setting InvalidScope is required")
	assert(t, c.ValidScope != "", "setting ValidScope is required")
	assert(t, c.ExceedingScope != "", "setting ExceedingScope is required")
	assert(t, c.InvalidToken != "", "setting InvalidToken is required")
	assert(t, c.UnknownToken != "", "setting UnknownToken is required")
	assert(t, c.ExpiredToken != "", "setting ExpiredToken is required")

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
		assert(t, c.InvalidRedirectURI != "", "setting InvalidRedirectURI is required")
		assert(t, c.PrimaryRedirectURI != "", "setting PrimaryRedirectURI is required")
		assert(t, c.SecondaryRedirectURI != "", "setting SecondaryRedirectURI is required")

		t.Run("AuthorizationEndpointTest", func(t *testing.T) {
			AuthorizationEndpointTest(t, c)
		})
	}

	if c.PasswordGrantSupport {
		assert(t, c.ResourceOwnerUsername != "", "setting ResourceOwnerUsername is required")
		assert(t, c.ResourceOwnerPassword != "", "setting ResourceOwnerPassword is required")

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
		assert(t, c.InvalidAuthorizationParams != nil || c.InvalidAuthorizationHeaders != nil, "setting InvalidAuthorizationParams or InvalidAuthorizationHeaders is required")
		assert(t, c.ValidAuthorizationParams != nil || c.ValidAuthorizationHeaders != nil, "setting ValidAuthorizationParams ValidAuthorizationHeaders is required")

		t.Run("ImplicitGrantTest", func(t *testing.T) {
			ImplicitGrantTest(t, c)
		})
	}

	if c.AuthorizationCodeGrantSupport {
		assert(t, c.InvalidAuthorizationParams != nil || c.InvalidAuthorizationHeaders != nil, "setting InvalidAuthorizationParams or InvalidAuthorizationHeaders is required")
		assert(t, c.ValidAuthorizationParams != nil || c.ValidAuthorizationHeaders != nil, "setting ValidAuthorizationParams ValidAuthorizationHeaders is required")
		assert(t, c.InvalidAuthorizationCode != "", "setting InvalidAuthorizationCode is required")
		assert(t, c.UnknownAuthorizationCode != "", "setting UnknownAuthorizationCode is required")
		assert(t, c.ExpiredAuthorizationCode != "", "setting ExpiredAuthorizationCode is required")

		t.Run("AuthorizationCodeGrantTest", func(t *testing.T) {
			AuthorizationCodeGrantTest(t, c)
		})
	}

	if c.RefreshTokenGrantSupport {
		assert(t, c.InvalidRefreshToken != "", "setting InvalidRefreshToken is required")
		assert(t, c.UnknownRefreshToken != "", "setting UnknownRefreshToken is required")
		assert(t, c.ValidRefreshToken != "", "setting ValidRefreshToken is required")
		assert(t, c.ExpiredRefreshToken != "", "setting ExpiredRefreshToken is required")

		t.Run("RefreshTokenGrantTest", func(t *testing.T) {
			RefreshTokenGrantTest(t, c)
		})
	}

	if c.RevocationEndpoint != "" {
		t.Run("RevocationEndpointTest", func(t *testing.T) {
			RevocationEndpointTest(t, c)
		})
	}
}
