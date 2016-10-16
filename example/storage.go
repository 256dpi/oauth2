package main

import (
	"time"

	"github.com/gonfire/oauth2"
	"golang.org/x/crypto/bcrypt"
)

type owner struct {
	id          string
	secret      []byte
	redirectURI string
}

var clients = map[string]owner{
	"client1": {
		id:          "client1",
		secret:      mustHash("foo"),
		redirectURI: "http://example.com/callback",
	},
}

var users = map[string]owner{
	"user1": {
		id:     "user1",
		secret: mustHash("foo"),
	},
}

type token struct {
	clientID  string
	username  string
	signature string
	expiresAt time.Time
	scope     oauth2.Scope
}

var accessTokens = make(map[string]token)

var refreshTokens = make(map[string]token)

var authorizationCodes = make(map[string]token)

func mustHash(password string) []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 0)
	if err != nil {
		panic(err)
	}

	return hash
}

func sameHash(hash []byte, password string) bool {
	return bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
}
