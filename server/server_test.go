package server

import (
	"net/http"
	"testing"
	"time"

	"github.com/256dpi/oauth2"
	"github.com/256dpi/oauth2/spec"
)

func TestSpec(t *testing.T) {
	allowedScope := oauth2.Scope{"foo", "bar"}
	requiredScope := oauth2.Scope{"foo"}

	serverConfig := Default([]byte("secret"), allowedScope)

	server := NewServer(serverConfig)

	server.AddClient(&Entity{
		ID:           "client1",
		Secret:       MustHash("foo"),
		RedirectURI:  "http://example.com/callback1",
		Confidential: true,
	})

	server.AddClient(&Entity{
		ID:           "client2",
		Secret:       MustHash("foo"),
		RedirectURI:  "http://example.com/callback2",
		Confidential: false,
	})

	server.AddUser(&Entity{
		ID:     "user1",
		Secret: MustHash("foo"),
	})

	unknownToken := serverConfig.MustGenerate()
	validToken := serverConfig.MustGenerate()
	expiredToken := serverConfig.MustGenerate()
	insufficientToken := serverConfig.MustGenerate()

	server.AddAccessToken(&Credential{
		ClientID:  "client1",
		Signature: validToken.SignatureString(),
		Scope:     allowedScope,
		ExpiresAt: time.Now().Add(time.Hour),
	})

	server.AddAccessToken(&Credential{
		ClientID:  "client1",
		Signature: expiredToken.SignatureString(),
		Scope:     allowedScope,
		ExpiresAt: time.Now().Add(-time.Hour),
	})

	server.AddAccessToken(&Credential{
		ClientID:  "client1",
		Signature: insufficientToken.SignatureString(),
		Scope:     oauth2.Scope{},
		ExpiresAt: time.Now().Add(time.Hour),
	})

	unknownRefreshToken := serverConfig.MustGenerate()
	validRefreshToken := serverConfig.MustGenerate()
	expiredRefreshToken := serverConfig.MustGenerate()

	server.AddRefreshToken(&Credential{
		ClientID:  "client1",
		Signature: validRefreshToken.SignatureString(),
		Scope:     allowedScope,
		ExpiresAt: time.Now().Add(time.Hour),
	})

	server.AddRefreshToken(&Credential{
		ClientID:  "client1",
		Signature: expiredRefreshToken.SignatureString(),
		Scope:     allowedScope,
		ExpiresAt: time.Now().Add(-time.Hour),
	})

	unknownAuthorizationCode := serverConfig.MustGenerate()
	expiredAuthorizationCode := serverConfig.MustGenerate()

	server.AddAuthorizationCode(&Credential{
		ClientID:  "client1",
		Signature: expiredAuthorizationCode.SignatureString(),
		Scope:     allowedScope,
		ExpiresAt: time.Now().Add(-time.Hour),
	})

	handler := http.NewServeMux()
	handler.Handle("/oauth2/", server)
	handler.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) {
		if server.Authorize(w, r, requiredScope) {
			_, _ = w.Write([]byte("OK"))
		}
	})

	specConfig := spec.Default(handler)

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

	spec.Run(t, specConfig)
}
