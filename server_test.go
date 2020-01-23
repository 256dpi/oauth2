package oauth2

import (
	"net/http"
	"testing"
	"time"

	"github.com/256dpi/oauth2/v2/oauth2test"
)

func TestServer(t *testing.T) {
	allowedScope := Scope{"foo", "bar"}
	requiredScope := Scope{"foo"}

	config := DefaultServerConfig([]byte("secret"), allowedScope)

	server := NewServer(config)

	server.Clients["client1"] = &ServerEntity{
		Secret:       "foo",
		RedirectURI:  "http://example.com/callback1",
		Confidential: true,
	}

	server.Clients["client2"] = &ServerEntity{
		Secret:       "foo",
		RedirectURI:  "http://example.com/callback2",
		Confidential: false,
	}

	server.Users["user1"] = &ServerEntity{
		Secret: "foo",
	}

	unknownToken := config.MustGenerate()
	validToken := config.MustGenerate()
	expiredToken := config.MustGenerate()
	insufficientToken := config.MustGenerate()

	server.AccessTokens[validToken.SignatureString()] = &ServerCredential{
		ClientID:  "client1",
		Scope:     allowedScope,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	server.AccessTokens[expiredToken.SignatureString()] = &ServerCredential{
		ClientID:  "client1",
		Scope:     allowedScope,
		ExpiresAt: time.Now().Add(-time.Hour),
	}

	server.AccessTokens[insufficientToken.SignatureString()] = &ServerCredential{
		ClientID:  "client1",
		Scope:     Scope{},
		ExpiresAt: time.Now().Add(time.Hour),
	}

	unknownRefreshToken := config.MustGenerate()
	validRefreshToken := config.MustGenerate()
	expiredRefreshToken := config.MustGenerate()

	server.RefreshTokens[validRefreshToken.SignatureString()] = &ServerCredential{
		ClientID:  "client1",
		Scope:     allowedScope,
		ExpiresAt: time.Now().Add(time.Hour),
	}

	server.RefreshTokens[expiredRefreshToken.SignatureString()] = &ServerCredential{
		ClientID:  "client1",
		Scope:     allowedScope,
		ExpiresAt: time.Now().Add(-time.Hour),
	}

	unknownAuthorizationCode := config.MustGenerate()
	expiredAuthorizationCode := config.MustGenerate()

	server.AuthorizationCodes[expiredAuthorizationCode.SignatureString()] = &ServerCredential{
		ClientID:  "client1",
		Scope:     allowedScope,
		ExpiresAt: time.Now().Add(-time.Hour),
	}

	handler := http.NewServeMux()
	handler.Handle("/oauth2/", server)
	handler.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		if server.Authorize(w, r, requiredScope) {
			_, _ = w.Write([]byte("OK"))
		}
	})

	spec := oauth2test.Default(handler)

	spec.PasswordGrantSupport = true
	spec.ClientCredentialsGrantSupport = true
	spec.ImplicitGrantSupport = true
	spec.AuthorizationCodeGrantSupport = true
	spec.RefreshTokenGrantSupport = true

	spec.ConfidentialClientID = "client1"
	spec.ConfidentialClientSecret = "foo"
	spec.PublicClientID = "client2"

	spec.ResourceOwnerUsername = "user1"
	spec.ResourceOwnerPassword = "foo"

	spec.InvalidScope = "baz"
	spec.ValidScope = "foo bar"
	spec.ExceedingScope = "foo bar baz"

	spec.ExpectedExpiresIn = int(config.AccessTokenLifespan / time.Second)

	spec.InvalidToken = "invalid"
	spec.UnknownToken = unknownToken.String()
	spec.ValidToken = validToken.String()
	spec.ExpiredToken = expiredToken.String()
	spec.InsufficientToken = insufficientToken.String()

	spec.InvalidRedirectURI = "http://invalid.com"
	spec.PrimaryRedirectURI = "http://example.com/callback1"
	spec.SecondaryRedirectURI = "http://example.com/callback2"

	spec.InvalidRefreshToken = "invalid"
	spec.UnknownRefreshToken = unknownRefreshToken.String()
	spec.ValidRefreshToken = validRefreshToken.String()
	spec.ExpiredRefreshToken = expiredRefreshToken.String()

	spec.InvalidAuthorizationCode = "invalid"
	spec.UnknownAuthorizationCode = unknownAuthorizationCode.String()
	spec.ExpiredAuthorizationCode = expiredAuthorizationCode.String()

	spec.InvalidAuthorizationParams = map[string]string{
		"username": "user1",
		"password": "invalid",
	}

	spec.ValidAuthorizationParams = map[string]string{
		"username": "user1",
		"password": "foo",
	}

	spec.CodeReplayMitigation = true

	oauth2test.Run(t, spec)
}
