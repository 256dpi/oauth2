// Package example implements a basic in-memory OAuth2 authentication server.
//
// The example can be used as a template to build a custom implementation of an
// OAuth2 compatible authentication server.
package example

import (
	"net/http"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/256dpi/oauth2"
	"github.com/256dpi/oauth2/bearer"
	"github.com/256dpi/oauth2/hmacsha"
	"github.com/256dpi/oauth2/revocation"
)

var secret = []byte("secret")

var tokenLifespan = time.Hour
var refreshTokenLifeSpan = 7 * 24 * time.Hour
var authorizationCodeLifespan = 10 * time.Minute

var allowedScope = oauth2.ParseScope("foo bar")
var requiredScope = oauth2.ParseScope("foo")

type owner struct {
	id           string
	secret       []byte
	redirectURI  string
	confidential bool
}

var clients = map[string]owner{}
var users = map[string]owner{}

type credential struct {
	clientID    string
	username    string
	signature   string
	expiresAt   time.Time
	scope       oauth2.Scope
	redirectURI string
}

var accessTokens = make(map[string]credential)
var refreshTokens = make(map[string]credential)
var authorizationCodes = make(map[string]credential)

func addOwner(list map[string]owner, o owner) owner {
	list[o.id] = o
	return o
}

func addCredential(list map[string]credential, t credential) credential {
	list[t.signature] = t
	return t
}

func sameHash(hash []byte, str string) bool {
	return bcrypt.CompareHashAndPassword(hash, []byte(str)) == nil
}

func newHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", tokenEndpoint)
	mux.HandleFunc("/oauth2/authorize", authorizationEndpoint)
	mux.HandleFunc("/oauth2/revoke", revocationEndpoint)
	mux.HandleFunc("/api/protected", protectedResource)
	return mux
}

func authorizationEndpoint(w http.ResponseWriter, r *http.Request) {
	// parse authorization request
	req, err := oauth2.ParseAuthorizationRequest(r)
	if err != nil {
		_ = oauth2.WriteError(w, err)
		return
	}

	// make sure the response type is known
	if !oauth2.KnownResponseType(req.ResponseType) {
		_ = oauth2.WriteError(w, oauth2.InvalidRequest("unknown response type"))
		return
	}

	// get client
	client, found := clients[req.ClientID]
	if !found {
		_ = oauth2.WriteError(w, oauth2.InvalidClient("unknown client"))
		return
	}

	// validate redirect uri
	if client.redirectURI != req.RedirectURI {
		_ = oauth2.WriteError(w, oauth2.InvalidRequest("invalid redirect URI"))
		return
	}

	// show notice for a GET request
	if r.Method == "GET" {
		_, _ = w.Write([]byte("This authentication server does not provide an authorization form.\n" +
			"Please submit the resource owners username and password in a POST request."))
		return
	}

	// read username and password
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")

	// triage based on response type
	switch req.ResponseType {
	case oauth2.TokenResponseType:
		handleImplicitGrant(w, username, password, req)
	case oauth2.CodeResponseType:
		handleAuthorizationCodeGrantAuthorization(w, username, password, req)
	}
}

func handleImplicitGrant(w http.ResponseWriter, username, password string, rq *oauth2.AuthorizationRequest) {
	// validate scope
	if !allowedScope.Includes(rq.Scope) {
		_ = oauth2.WriteError(w, oauth2.InvalidScope("").SetRedirect(rq.RedirectURI, rq.State, true))
		return
	}

	// validate user credentials
	owner, found := users[username]
	if !found || !sameHash(owner.secret, password) {
		_ = oauth2.WriteError(w, oauth2.AccessDenied("").SetRedirect(rq.RedirectURI, rq.State, true))
		return
	}

	// issue tokens
	r := issueTokens(false, rq.Scope, rq.ClientID, owner.id)

	// redirect token
	r.SetRedirect(rq.RedirectURI, rq.State)

	// write response
	_ = oauth2.WriteTokenResponse(w, r)
}

func handleAuthorizationCodeGrantAuthorization(w http.ResponseWriter, username, password string, rq *oauth2.AuthorizationRequest) {
	// validate scope
	if !allowedScope.Includes(rq.Scope) {
		_ = oauth2.WriteError(w, oauth2.InvalidScope("").SetRedirect(rq.RedirectURI, rq.State, false))
		return
	}

	// validate user credentials
	owner, found := users[username]
	if !found || !sameHash(owner.secret, password) {
		_ = oauth2.WriteError(w, oauth2.AccessDenied("").SetRedirect(rq.RedirectURI, rq.State, false))
		return
	}

	// generate new authorization code
	authorizationCode := hmacsha.MustGenerate(secret, 32)

	// prepare response
	r := oauth2.NewCodeResponse(authorizationCode.String(), rq.RedirectURI, rq.State)

	// save authorization code
	authorizationCodes[authorizationCode.SignatureString()] = credential{
		clientID:    rq.ClientID,
		username:    owner.id,
		signature:   authorizationCode.SignatureString(),
		expiresAt:   time.Now().Add(authorizationCodeLifespan),
		scope:       rq.Scope,
		redirectURI: rq.RedirectURI,
	}

	// write response
	_ = oauth2.WriteCodeResponse(w, r)
}

func tokenEndpoint(w http.ResponseWriter, r *http.Request) {
	// parse token request
	req, err := oauth2.ParseTokenRequest(r)
	if err != nil {
		_ = oauth2.WriteError(w, err)
		return
	}

	// make sure the grant type is known
	if !oauth2.KnownGrantType(req.GrantType) {
		_ = oauth2.WriteError(w, oauth2.InvalidRequest("unknown grant type"))
		return
	}

	// find client
	client, found := clients[req.ClientID]
	if !found {
		_ = oauth2.WriteError(w, oauth2.InvalidClient("unknown client"))
		return
	}

	// authenticate client
	if client.confidential && !sameHash(client.secret, req.ClientSecret) {
		_ = oauth2.WriteError(w, oauth2.InvalidClient("unknown client"))
		return
	}

	// handle grant type
	switch req.GrantType {
	case oauth2.PasswordGrantType:
		handleResourceOwnerPasswordCredentialsGrant(w, req)
	case oauth2.ClientCredentialsGrantType:
		handleClientCredentialsGrant(w, req)
	case oauth2.AuthorizationCodeGrantType:
		handleAuthorizationCodeGrant(w, req)
	case oauth2.RefreshTokenGrantType:
		handleRefreshTokenGrant(w, req)
	}
}

func handleResourceOwnerPasswordCredentialsGrant(w http.ResponseWriter, rq *oauth2.TokenRequest) {
	// authenticate resource owner
	owner, found := users[rq.Username]
	if !found || !sameHash(owner.secret, rq.Password) {
		_ = oauth2.WriteError(w, oauth2.AccessDenied(""))
		return
	}

	// check scope
	if !allowedScope.Includes(rq.Scope) {
		_ = oauth2.WriteError(w, oauth2.InvalidScope(""))
		return
	}

	// issue tokens
	r := issueTokens(true, rq.Scope, rq.ClientID, rq.Username)

	// write response
	_ = oauth2.WriteTokenResponse(w, r)
}

func handleClientCredentialsGrant(w http.ResponseWriter, rq *oauth2.TokenRequest) {
	// check scope
	if !allowedScope.Includes(rq.Scope) {
		_ = oauth2.WriteError(w, oauth2.InvalidScope(""))
		return
	}

	// save tokens
	r := issueTokens(true, rq.Scope, rq.ClientID, "")

	// write response
	_ = oauth2.WriteTokenResponse(w, r)
}

func handleAuthorizationCodeGrant(w http.ResponseWriter, rq *oauth2.TokenRequest) {
	// parse authorization code
	authorizationCode, err := hmacsha.Parse(secret, rq.Code)
	if err != nil {
		_ = oauth2.WriteError(w, oauth2.InvalidRequest(err.Error()))
		return
	}

	// get stored authorization code by signature
	storedAuthorizationCode, found := authorizationCodes[authorizationCode.SignatureString()]
	if !found {
		_ = oauth2.WriteError(w, oauth2.InvalidGrant("unknown authorization code"))
		return
	}

	// validate expiration
	if storedAuthorizationCode.expiresAt.Before(time.Now()) {
		_ = oauth2.WriteError(w, oauth2.InvalidGrant("expired authorization code"))
		return
	}

	// validate ownership
	if storedAuthorizationCode.clientID != rq.ClientID {
		_ = oauth2.WriteError(w, oauth2.InvalidGrant("invalid authorization code ownership"))
		return
	}

	// validate redirect uri
	if storedAuthorizationCode.redirectURI != rq.RedirectURI {
		_ = oauth2.WriteError(w, oauth2.InvalidGrant("changed redirect uri"))
		return
	}

	// issue tokens
	r := issueTokens(true, storedAuthorizationCode.scope, rq.ClientID, storedAuthorizationCode.username)

	// delete used authorization code
	delete(authorizationCodes, authorizationCode.SignatureString())

	// write response
	_ = oauth2.WriteTokenResponse(w, r)
}

func handleRefreshTokenGrant(w http.ResponseWriter, rq *oauth2.TokenRequest) {
	// parse refresh token
	refreshToken, err := hmacsha.Parse(secret, rq.RefreshToken)
	if err != nil {
		_ = oauth2.WriteError(w, oauth2.InvalidRequest(err.Error()))
		return
	}

	// get stored refresh token by signature
	storedRefreshToken, found := refreshTokens[refreshToken.SignatureString()]
	if !found {
		_ = oauth2.WriteError(w, oauth2.InvalidGrant("unknown refresh token"))
		return
	}

	// validate expiration
	if storedRefreshToken.expiresAt.Before(time.Now()) {
		_ = oauth2.WriteError(w, oauth2.InvalidGrant("expired refresh token"))
		return
	}

	// validate ownership
	if storedRefreshToken.clientID != rq.ClientID {
		_ = oauth2.WriteError(w, oauth2.InvalidGrant("invalid refresh token ownership"))
		return
	}

	// inherit scope from stored refresh token
	if rq.Scope.Empty() {
		rq.Scope = storedRefreshToken.scope
	}

	// validate scope - a missing scope is always included
	if !storedRefreshToken.scope.Includes(rq.Scope) {
		_ = oauth2.WriteError(w, oauth2.InvalidScope("scope exceeds the originally granted scope"))
		return
	}

	// issue tokens
	r := issueTokens(true, rq.Scope, rq.ClientID, storedRefreshToken.username)

	// delete used refresh token
	delete(refreshTokens, refreshToken.SignatureString())

	// write response
	_ = oauth2.WriteTokenResponse(w, r)
}

func issueTokens(issueRefreshToken bool, scope oauth2.Scope, clientID, username string) *oauth2.TokenResponse {
	// generate new access token
	accessToken := hmacsha.MustGenerate(secret, 32)

	// generate new refresh token
	refreshToken := hmacsha.MustGenerate(secret, 32)

	// prepare response
	r := bearer.NewTokenResponse(accessToken.String(), int(tokenLifespan/time.Second))

	// set granted scope
	r.Scope = scope

	// set refresh token
	r.RefreshToken = refreshToken.String()

	// disable refresh token if not requested
	if !issueRefreshToken {
		refreshToken = nil
	}

	// save access token
	accessTokens[accessToken.SignatureString()] = credential{
		clientID:  clientID,
		username:  username,
		signature: accessToken.SignatureString(),
		expiresAt: time.Now().Add(tokenLifespan),
		scope:     scope,
	}

	// save refresh token if present
	if refreshToken != nil {
		refreshTokens[refreshToken.SignatureString()] = credential{
			clientID:  clientID,
			username:  username,
			signature: refreshToken.SignatureString(),
			expiresAt: time.Now().Add(refreshTokenLifeSpan),
			scope:     scope,
		}
	}

	return r
}

func revocationEndpoint(w http.ResponseWriter, r *http.Request) {
	// parse authorization request
	req, err := revocation.ParseRequest(r)
	if err != nil {
		_ = oauth2.WriteError(w, err)
		return
	}

	// get client
	client, found := clients[req.ClientID]
	if !found {
		_ = oauth2.WriteError(w, oauth2.InvalidClient("unknown client"))
		return
	}

	// parse token
	token, err := hmacsha.Parse(secret, req.Token)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	// revoke tokens
	revokeToken(client, accessTokens, token.SignatureString())
	revokeToken(client, refreshTokens, token.SignatureString())

	// write header
	w.WriteHeader(http.StatusOK)
}

func revokeToken(client owner, list map[string]credential, signature string) {
	// get token
	token, ok := list[signature]
	if !ok {
		return
	}

	// check client id
	if token.clientID != client.id {
		return
	}

	// remove token
	delete(list, signature)
}

func protectedResource(w http.ResponseWriter, r *http.Request) {
	// parse bearer token
	tk, err := bearer.ParseToken(r)
	if err != nil {
		_ = bearer.WriteError(w, err)
		return
	}

	// parse token
	token, err := hmacsha.Parse(secret, tk)
	if err != nil {
		_ = bearer.WriteError(w, bearer.InvalidToken("malformed token"))
		return
	}

	// get token
	accessToken, found := accessTokens[token.SignatureString()]
	if !found {
		_ = bearer.WriteError(w, bearer.InvalidToken("unknown token"))
		return
	}

	// validate expiration
	if accessToken.expiresAt.Before(time.Now()) {
		_ = bearer.WriteError(w, bearer.InvalidToken("expired token"))
		return
	}

	// validate scope
	if !accessToken.scope.Includes(requiredScope) {
		_ = bearer.WriteError(w, bearer.InsufficientScope(requiredScope.String()))
		return
	}

	// write response
	_, _ = w.Write([]byte("OK"))
}
