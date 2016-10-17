package main

import (
	"testing"
	"time"

	"github.com/gonfire/oauth2/spec"
)

func TestSpec(t *testing.T) {
	config := spec.Default(newHandler())

	config.PasswordGrant = true
	config.ClientCredentialsGrant = true
	config.ImplicitGrant = true
	config.AuthorizationCodeGrant = true

	config.ClientID = "client1"
	config.ClientSecret = "foo"
	config.OwnerUsername = "user1"
	config.OwnerPassword = "foo"
	config.ValidScope = "foo bar"
	config.ExpectedExpireIn = int(tokenLifespan / time.Second)
	config.RedirectURI = "http://example.com/callback"

	config.ValidTokenAuthorization = map[string]string{
		"username": config.OwnerUsername,
		"password": config.OwnerPassword,
	}

	config.ValidCodeAuthorization = map[string]string{
		"username": config.OwnerUsername,
		"password": config.OwnerPassword,
	}

	spec.Run(t, config)
}
