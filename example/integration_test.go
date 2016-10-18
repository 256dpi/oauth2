package main

import (
	"testing"
	"time"

	"github.com/gonfire/oauth2"
	"github.com/gonfire/oauth2/spec"
	"golang.org/x/crypto/bcrypt"
)

func TestSpec(t *testing.T) {
	addOwner(clients, owner{
		id:          "client1",
		secret:      mustHash("foo"),
		redirectURI: "http://example.com/callback1",
	})

	addOwner(clients, owner{
		id:          "client2",
		secret:      mustHash("foo"),
		redirectURI: "http://example.com/callback2",
	})

	addOwner(users, owner{
		id:     "user1",
		secret: mustHash("foo"),
	})

	addOwner(users, owner{
		id:     "user2",
		secret: mustHash("foo"),
	})

	unknownAuthorizationCode := mustGenerateToken()
	expiredAuthorizationCode := mustGenerateToken()

	addToken(authorizationCodes, token{
		clientID:  "client1",
		signature: expiredAuthorizationCode.SignatureString(),
		scope:     allowedScope,
		expiresAt: time.Now().Add(-time.Hour),
	})

	unknownRefreshToken := mustGenerateToken()
	validRefreshToken := mustGenerateToken()
	expiredRefreshToken := mustGenerateToken()

	addToken(refreshTokens, token{
		clientID:  "client1",
		signature: validRefreshToken.SignatureString(),
		scope:     allowedScope,
		expiresAt: time.Now().Add(time.Hour),
	})

	addToken(refreshTokens, token{
		clientID:  "client1",
		signature: expiredRefreshToken.SignatureString(),
		scope:     allowedScope,
		expiresAt: time.Now().Add(-time.Hour),
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

	config.ResourceOwnerUsername = "user1"
	config.ResourceOwnerPassword = "foo"

	config.InvalidScope = "baz"
	config.ValidScope = "foo bar"
	config.ExceedingScope = "foo bar baz"

	config.ExpectedExpireIn = int(tokenLifespan / time.Second)

	config.InvalidRedirectURI = "http://invalid.com"
	config.PrimaryRedirectURI = "http://example.com/callback1"
	config.SecondaryRedirectURI = "http://example.com/callback2"

	config.InvalidRefreshToken = "invalid"
	config.UnknownRefreshToken = unknownRefreshToken.String()
	config.ValidRefreshToken = validRefreshToken.String()
	config.ExpiredRefreshToken = expiredRefreshToken.String()

	config.InvalidAuthorizationCode = "invalid"
	config.UnknownAuthorizationCode = unknownAuthorizationCode.String()
	config.ExpiredAuthorizationCode = expiredAuthorizationCode.String()

	config.TokenAuthorizationParams = map[string]string{
		"username": "user1",
		"password": "foo",
	}

	config.CodeAuthorizationParams = map[string]string{
		"username": "user1",
		"password": "foo",
	}

	spec.Run(t, config)
}

func mustHash(password string) []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		panic(err)
	}

	return hash
}

func mustGenerateToken() *oauth2.Token {
	token, err := oauth2.GenerateToken(secret, 16)
	if err != nil {
		panic(err)
	}

	return token
}
