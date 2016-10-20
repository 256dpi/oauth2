package server

import (
	"time"

	"github.com/gonfire/oauth2"
	"golang.org/x/crypto/bcrypt"
)

type owner struct {
	id           string
	secret       []byte
	redirectURI  string
	confidential bool
}

func (o *owner) ID() string {
	return o.id
}

func (o *owner) Confidential() bool {
	return o.confidential
}

func (o *owner) ValidSecret(pw string) bool {
	return sameHash(o.secret, pw)
}

func (o *owner) Username() string {
	return o.id
}

var clients = map[string]*owner{}
var users = map[string]*owner{}

type token struct {
	clientID        string
	resourceOwnerID string
	signature       string
	expiresAt       time.Time
	scope           oauth2.Scope
	redirectURI     string
}

func (t *token) ClientID() string {
	return t.clientID
}

func (t *token) ResourceOwnerID() string {
	return t.resourceOwnerID
}

func (t *token) ExpiresAt() time.Time {
	return t.expiresAt
}

func (t *token) Scope() oauth2.Scope {
	return t.scope
}

func (t *token) RedirectURI() string {
	return t.redirectURI
}

var accessTokens = make(map[string]*token)
var refreshTokens = make(map[string]*token)
var authorizationCodes = make(map[string]*token)

func addOwner(list map[string]*owner, o *owner) *owner {
	list[o.id] = o
	return o
}

func addToken(list map[string]*token, t *token) *token {
	list[t.signature] = t
	return t
}

func sameHash(hash []byte, password string) bool {
	return bcrypt.CompareHashAndPassword(hash, []byte(password)) == nil
}
