package main

import (
	"testing"
	"time"

	"github.com/gonfire/oauth2/spec"
)

func TestSpec(t *testing.T) {
	addOwner(clients, owner{
		id:          "client1",
		secret:      mustHash("foo"),
		redirectURI: "http://example.com/callback",
	})

	addOwner(clients, owner{
		id:          "client2",
		secret:      mustHash("foo"),
		redirectURI: "http://example.com/callback",
	})

	addOwner(users, owner{
		id:     "user1",
		secret: mustHash("foo"),
	})

	addOwner(users, owner{
		id:     "user2",
		secret: mustHash("foo"),
	})

	invalidRefreshToken := mustGenerateToken()
	validRefreshToken := mustGenerateToken()

	addToken(refreshTokens, token{
		clientID:  "client1",
		signature: validRefreshToken.SignatureString(),
		scope:     allowedScope,
		expiresAt: time.Now().Add(time.Hour),
	})

	config := spec.Default(newHandler())

	config.PasswordGrantSupport = true
	config.ClientCredentialsGrantSupport = true
	config.ImplicitGrantSupport = true
	config.AuthorizationCodeGrantSupport = true
	config.RefreshTokenGrantSupport = true

	config.PrimaryClientID = "client1"
	config.PrimaryClientSecret = "foo"
	config.SecondaryClientID = "client2"
	config.SecondaryClientSecret = "foo"

	config.PrimaryResourceOwnerUsername = "user1"
	config.PrimaryResourceOwnerPassword = "foo"
	config.SecondaryResourceOwnerUsername = "user2"
	config.SecondaryResourceOwnerPassword = "foo"

	config.InvalidScope = "baz"
	config.ValidScope = "foo bar"
	config.ExceedingScope = "foo bar baz"

	config.ExpectedExpireIn = int(tokenLifespan / time.Second)

	config.InvalidRedirectURI = "http://invalid.com"
	config.ValidRedirectURI = "http://example.com/callback"

	config.InvalidRefreshToken = invalidRefreshToken.String()
	config.ValidRefreshToken = validRefreshToken.String()

	config.TokenAuthorizationParams = map[string]string{
		"username": config.PrimaryResourceOwnerUsername,
		"password": config.PrimaryResourceOwnerPassword,
	}

	config.CodeAuthorizationParams = map[string]string{
		"username": config.PrimaryResourceOwnerUsername,
		"password": config.PrimaryResourceOwnerPassword,
	}

	spec.Run(t, config)
}
