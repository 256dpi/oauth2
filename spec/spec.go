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

	PasswordGrant           bool
	ClientCredentialsGrant  bool
	ImplicitGrant           bool
	AuthorizationCodeGrant  bool
	RequiresConfidentiality bool

	ClientID         string
	ClientSecret     string
	OwnerUsername    string
	OwnerPassword    string
	ValidScope       string
	ExpectedExpireIn int
	RedirectURI      string

	ValidTokenAuthorization map[string]string
	ValidCodeAuthorization  map[string]string
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

	if c.RequiresConfidentiality {
		t.Run("ConfidentialClientTest", func(t *testing.T) {
			ConfidentialClientTest(t, c)
		})
	}
}
