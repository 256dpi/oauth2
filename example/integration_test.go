package main

import (
	"testing"

	"github.com/gonfire/oauth2/spec"
	"time"
)

func TestSpec(t *testing.T) {
	config := spec.Default(newHandler())
	config.ClientID = "client1"
	config.ClientSecret = "foo"
	config.OwnerUsername = "user1"
	config.OwnerPassword = "foo"
	config.PasswordGrant = true
	config.ValidScope = "foo bar"
	config.ExpectedExpireIn = int(tokenLifespan / time.Second)

	spec.Run(t, config)
}
