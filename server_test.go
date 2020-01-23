package oauth2

import (
	"net/http"
	"testing"
	"time"

	"github.com/256dpi/oauth2/oauth2test"
)

func TestSpec(t *testing.T) {
	allowedScope := Scope{"foo", "bar"}
	requiredScope := Scope{"foo"}

	serverConfig := DefaultServerConfig([]byte("secret"), allowedScope)

	server := NewServer(serverConfig)

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

	unknownToken := serverConfig.MustGenerate()
	validToken := serverConfig.MustGenerate()
	expiredToken := serverConfig.MustGenerate()
	insufficientToken := serverConfig.MustGenerate()

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

	unknownRefreshToken := serverConfig.MustGenerate()
	validRefreshToken := serverConfig.MustGenerate()
	expiredRefreshToken := serverConfig.MustGenerate()

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

	unknownAuthorizationCode := serverConfig.MustGenerate()
	expiredAuthorizationCode := serverConfig.MustGenerate()

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

	specConfig := oauth2test.Default(handler)

	specConfig.PasswordGrantSupport = true
	specConfig.ClientCredentialsGrantSupport = true
	specConfig.ImplicitGrantSupport = true
	specConfig.AuthorizationCodeGrantSupport = true
	specConfig.RefreshTokenGrantSupport = true

	specConfig.ConfidentialClientID = "client1"
	specConfig.ConfidentialClientSecret = "foo"
	specConfig.PublicClientID = "client2"

	specConfig.ResourceOwnerUsername = "user1"
	specConfig.ResourceOwnerPassword = "foo"

	specConfig.InvalidScope = "baz"
	specConfig.ValidScope = "foo bar"
	specConfig.ExceedingScope = "foo bar baz"

	specConfig.ExpectedExpiresIn = int(serverConfig.AccessTokenLifespan / time.Second)

	specConfig.InvalidToken = "invalid"
	specConfig.UnknownToken = unknownToken.String()
	specConfig.ValidToken = validToken.String()
	specConfig.ExpiredToken = expiredToken.String()
	specConfig.InsufficientToken = insufficientToken.String()

	specConfig.InvalidRedirectURI = "http://invalid.com"
	specConfig.PrimaryRedirectURI = "http://example.com/callback1"
	specConfig.SecondaryRedirectURI = "http://example.com/callback2"

	specConfig.InvalidRefreshToken = "invalid"
	specConfig.UnknownRefreshToken = unknownRefreshToken.String()
	specConfig.ValidRefreshToken = validRefreshToken.String()
	specConfig.ExpiredRefreshToken = expiredRefreshToken.String()

	specConfig.InvalidAuthorizationCode = "invalid"
	specConfig.UnknownAuthorizationCode = unknownAuthorizationCode.String()
	specConfig.ExpiredAuthorizationCode = expiredAuthorizationCode.String()

	specConfig.InvalidAuthorizationParams = map[string]string{
		"username": "user1",
		"password": "invalid",
	}

	specConfig.ValidAuthorizationParams = map[string]string{
		"username": "user1",
		"password": "foo",
	}

	specConfig.CodeReplayMitigation = true

	oauth2test.Run(t, specConfig)
}
