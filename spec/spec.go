package spec

import (
	"net/http"
	"testing"
)

type Config struct {
	Handler http.Handler

	TokenEndpoint     string
	AuthorizeEndpoint string
	ProtectedResource string

	PasswordGrant          bool
	ClientCredentialsGrant bool
	ImplicitGrant          bool
	AuthorizationCodeGrant bool

	ClientID         string
	ClientSecret     string
	OwnerUsername    string
	OwnerPassword    string
	ValidScope       string
	ExpectedExpireIn int
}

func Default(handler http.Handler) *Config {
	return &Config{
		Handler:           handler,
		TokenEndpoint:     "/oauth2/token",
		AuthorizeEndpoint: "/oauth2/authorize",
		ProtectedResource: "/api/protected",
	}
}

func Run(t *testing.T, c *Config) {
	t.Run("ProtectedResourceTest", func(t *testing.T) {
		UnauthorizedAccessTest(t, c)
	})

	t.Run("UnsupportedGrantTypeTest", func(t *testing.T) {
		UnsupportedGrantTypeTest(t, c)
	})

	if c.PasswordGrant {
		t.Run("PasswordGrantTest", func(t *testing.T) {
			PasswordGrantTest(t, c)
		})
	}
}
