// Package oauth2test implements reusable integration tests to run against any
// OAuth2 authentication server.
package oauth2test

import (
	"net/http"
	"testing"
)

// Spec declares the needed info for testing an OAuth2 authentication server.
type Spec struct {
	// The server handler.
	Handler http.Handler

	// The token endpoint (e.g. /oauth2/token).
	TokenEndpoint string

	// The authorization endpoint (e.g. /oauth2/authorize).
	AuthorizeEndpoint string

	// The revocation endpoint (e.g. /oauth2/revoke).
	RevocationEndpoint string

	// The introspection endpoint (e.g. /oauth2/introspect).
	IntrospectionEndpoint string

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
	ValidToken        string
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

// Default returns a common used spec that can be taken as a basis.
func Default(handler http.Handler) *Spec {
	return &Spec{
		Handler:               handler,
		TokenEndpoint:         "/oauth2/token",
		AuthorizeEndpoint:     "/oauth2/authorize",
		RevocationEndpoint:    "/oauth2/revoke",
		IntrospectionEndpoint: "/oauth2/introspect",
		ProtectedResource:     "/api/protected",
		ExpectedExpiresIn:     3600,
		InvalidToken:          "invalid",
		InvalidRedirectURI:    "http://invalid.com",
		InvalidRefreshToken:   "invalid",
	}
}

// Run will run all tests using the specified spec.
func Run(t *testing.T, spec *Spec) {
	// validate spec
	must(spec.Handler != nil, "setting Handler is required")
	must(spec.TokenEndpoint != "", "setting TokenEndpoint is required")
	must(spec.AuthorizeEndpoint != "", "setting AuthorizeEndpoint is required")
	must(spec.ProtectedResource != "", "setting ProtectedResource is required")
	must(spec.ConfidentialClientID != "", "setting ConfidentialClientID is required")
	must(spec.ConfidentialClientSecret != "", "setting ConfidentialClientSecret is required")
	must(spec.PublicClientID != "", "setting PublicClientID is required")
	must(spec.InvalidScope != "", "setting InvalidScope is required")
	must(spec.ValidScope != "", "setting ValidScope is required")
	must(spec.ExceedingScope != "", "setting ExceedingScope is required")
	must(spec.InvalidToken != "", "setting InvalidToken is required")
	must(spec.ValidToken != "", "setting ValidToken is required")
	must(spec.UnknownToken != "", "setting UnknownToken is required")
	must(spec.ExpiredToken != "", "setting ExpiredToken is required")

	t.Run("ProtectedResourceTest", func(t *testing.T) {
		ProtectedResourceTest(t, spec)
	})

	if spec.PasswordGrantSupport || spec.ClientCredentialsGrantSupport ||
		spec.AuthorizationCodeGrantSupport || spec.RefreshTokenGrantSupport {
		t.Run("TokenEndpointTest", func(t *testing.T) {
			TokenEndpointTest(t, spec)
		})
	}

	if spec.ImplicitGrantSupport || spec.AuthorizationCodeGrantSupport {
		must(spec.InvalidRedirectURI != "", "setting InvalidRedirectURI is required")
		must(spec.PrimaryRedirectURI != "", "setting PrimaryRedirectURI is required")
		must(spec.SecondaryRedirectURI != "", "setting SecondaryRedirectURI is required")

		t.Run("AuthorizationEndpointTest", func(t *testing.T) {
			AuthorizationEndpointTest(t, spec)
		})
	}

	if spec.PasswordGrantSupport {
		must(spec.ResourceOwnerUsername != "", "setting ResourceOwnerUsername is required")
		must(spec.ResourceOwnerPassword != "", "setting ResourceOwnerPassword is required")

		t.Run("PasswordGrantTest", func(t *testing.T) {
			PasswordGrantTest(t, spec)
		})
	}

	if spec.ClientCredentialsGrantSupport {
		t.Run("ClientCredentialsGrantTest", func(t *testing.T) {
			ClientCredentialsGrantTest(t, spec)
		})
	}

	if spec.ImplicitGrantSupport {
		must(spec.InvalidAuthorizationParams != nil || spec.InvalidAuthorizationHeaders != nil, "setting InvalidAuthorizationParams or InvalidAuthorizationHeaders is required")
		must(spec.ValidAuthorizationParams != nil || spec.ValidAuthorizationHeaders != nil, "setting ValidAuthorizationParams ValidAuthorizationHeaders is required")

		t.Run("ImplicitGrantTest", func(t *testing.T) {
			ImplicitGrantTest(t, spec)
		})
	}

	if spec.AuthorizationCodeGrantSupport {
		must(spec.InvalidAuthorizationParams != nil || spec.InvalidAuthorizationHeaders != nil, "setting InvalidAuthorizationParams or InvalidAuthorizationHeaders is required")
		must(spec.ValidAuthorizationParams != nil || spec.ValidAuthorizationHeaders != nil, "setting ValidAuthorizationParams ValidAuthorizationHeaders is required")
		must(spec.InvalidAuthorizationCode != "", "setting InvalidAuthorizationCode is required")
		must(spec.UnknownAuthorizationCode != "", "setting UnknownAuthorizationCode is required")
		must(spec.ExpiredAuthorizationCode != "", "setting ExpiredAuthorizationCode is required")

		t.Run("AuthorizationCodeGrantTest", func(t *testing.T) {
			AuthorizationCodeGrantTest(t, spec)
		})
	}

	if spec.RefreshTokenGrantSupport {
		must(spec.InvalidRefreshToken != "", "setting InvalidRefreshToken is required")
		must(spec.UnknownRefreshToken != "", "setting UnknownRefreshToken is required")
		must(spec.ValidRefreshToken != "", "setting ValidRefreshToken is required")
		must(spec.ExpiredRefreshToken != "", "setting ExpiredRefreshToken is required")

		t.Run("RefreshTokenGrantTest", func(t *testing.T) {
			RefreshTokenGrantTest(t, spec)
		})
	}

	if spec.IntrospectionEndpoint != "" {
		t.Run("IntrospectionEndpointTest", func(t *testing.T) {
			IntrospectionEndpointTest(t, spec)
		})
	}

	if spec.RevocationEndpoint != "" {
		t.Run("RevocationEndpointTest", func(t *testing.T) {
			RevocationEndpointTest(t, spec)
		})
	}
}
