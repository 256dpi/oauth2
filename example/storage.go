package main

import (
	"time"

	"golang.org/x/crypto/bcrypt"
)

type owner struct {
	id     string
	secret string
}

var clients = map[string]owner{
	"client1": {
		id:     "client1",
		secret: mustHash("foo"),
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
}

var accessTokens = make(map[string]token)

var refreshTokens = make(map[string]token)

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