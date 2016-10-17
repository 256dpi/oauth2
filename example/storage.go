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

var clients = map[string]owner{}

var users = map[string]owner{}

type token struct {
	clientID    string
	username    string
	signature   string
	expiresAt   time.Time
	scope       oauth2.Scope
	redirectURI string
}

var accessTokens = make(map[string]token)

var refreshTokens = make(map[string]token)

var authorizationCodes = make(map[string]token)

func addOwner(list map[string]owner, o owner) owner {
	list[o.id] = o
	return o
}

func addToken(list map[string]token, t token) token {
	list[t.signature] = t
	return t
}

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

func mustGenerateToken() *oauth2.Token {
	token, err := oauth2.GenerateToken(secret, 16)
	if err != nil {
		panic(err)
	}

	return token
}
