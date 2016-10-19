package server

import (
	"net/http"
	"time"

	"github.com/gonfire/oauth2"
	"github.com/gonfire/oauth2/bearer"
	"github.com/gonfire/oauth2/hmacsha"
)

func authorizationEndpoint(w http.ResponseWriter, r *http.Request) {
	// parse authorization request
	req, err := oauth2.ParseAuthorizationRequest(r)
	if err != nil {
		oauth2.WriteError(w, err)
		return
	}

	// make sure the response type is known
	if !oauth2.KnownResponseType(req.ResponseType) {
		oauth2.WriteError(w, oauth2.InvalidRequest(req.State, "Unknown response type"))
		return
	}

	// get client
	client, found := clients[req.ClientID]
	if !found {
		oauth2.WriteError(w, oauth2.InvalidClient(req.State, "Unknown client"))
		return
	}

	// validate redirect uri
	if client.redirectURI != req.RedirectURI {
		oauth2.WriteError(w, oauth2.InvalidRequest(req.State, "Invalid redirect URI"))
		return
	}

	// show info notice on a GET request
	if r.Method == "GET" {
		w.Write([]byte("This authentication server does not provide an authorization form."))
		return
	}

	// triage based on response type
	switch req.ResponseType {
	case oauth2.TokenResponseType:
		handleImplicitGrant(w, r, req)
	case oauth2.CodeResponseType:
		handleAuthorizationCodeGrantAuthorization(w, r, req)
	}
}

func handleImplicitGrant(w http.ResponseWriter, r *http.Request, req *oauth2.AuthorizationRequest) {
	// validate scope
	if !allowedScope.Includes(req.Scope) {
		oauth2.RedirectError(w, req.RedirectURI, true, oauth2.InvalidScope(req.State, oauth2.NoDescription))
		return
	}

	// validate user credentials
	owner, found := users[r.PostForm.Get("username")]
	if !found || !sameHash(owner.secret, r.PostForm.Get("password")) {
		oauth2.RedirectError(w, req.RedirectURI, true, oauth2.AccessDenied(req.State, oauth2.NoDescription))
		return
	}

	// generate new access token
	accessToken := hmacsha.MustGenerate(secret, 32)

	// prepare response
	res := bearer.NewTokenResponse(accessToken.String(), int(tokenLifespan/time.Second))

	// set granted scope
	res.Scope = req.Scope

	// set state
	res.State = req.State

	// save access token
	accessTokens[accessToken.SignatureString()] = token{
		clientID:  req.ClientID,
		username:  owner.id,
		signature: accessToken.SignatureString(),
		expiresAt: time.Now().Add(tokenLifespan),
		scope:     req.Scope,
	}

	// write response
	oauth2.RedirectTokenResponse(w, req.RedirectURI, res)
}

func handleAuthorizationCodeGrantAuthorization(w http.ResponseWriter, r *http.Request, req *oauth2.AuthorizationRequest) {
	// validate scope
	if !allowedScope.Includes(req.Scope) {
		oauth2.RedirectError(w, req.RedirectURI, false, oauth2.InvalidScope(req.State, oauth2.NoDescription))
		return
	}

	// validate user credentials
	owner, found := users[r.PostForm.Get("username")]
	if !found || !sameHash(owner.secret, r.PostForm.Get("password")) {
		oauth2.RedirectError(w, req.RedirectURI, false, oauth2.AccessDenied(req.State, oauth2.NoDescription))
		return
	}

	// generate new authorization code
	authorizationCode := hmacsha.MustGenerate(secret, 32)

	// prepare response
	res := oauth2.NewCodeResponse(authorizationCode.String())

	// set state
	res.State = req.State

	// save authorization code
	authorizationCodes[authorizationCode.SignatureString()] = token{
		clientID:    req.ClientID,
		username:    owner.id,
		signature:   authorizationCode.SignatureString(),
		expiresAt:   time.Now().Add(authorizationCodeLifespan),
		scope:       req.Scope,
		redirectURI: req.RedirectURI,
	}

	// write response
	oauth2.RedirectCodeResponse(w, req.RedirectURI, res)
}

func tokenEndpoint(w http.ResponseWriter, r *http.Request) {
	// parse token request
	req, err := oauth2.ParseTokenRequest(r)
	if err != nil {
		oauth2.WriteError(w, err)
		return
	}

	// make sure the grant type is known
	if !oauth2.KnownGrantType(req.GrantType) {
		oauth2.WriteError(w, oauth2.InvalidRequest(req.State, "Unknown grant type"))
		return
	}

	// authenticate client
	client, found := clients[req.ClientID]
	if !found || !sameHash(client.secret, req.ClientSecret) {
		oauth2.WriteError(w, oauth2.InvalidClient(req.State, "Unknown client"))
		return
	}

	// at this point the authentication server may check if the authenticated
	// client is public or confidential
	//
	// see: req.Confidential()

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

func handleResourceOwnerPasswordCredentialsGrant(w http.ResponseWriter, req *oauth2.TokenRequest) {
	// authenticate resource owner
	owner, found := users[req.Username]
	if !found || !sameHash(owner.secret, req.Password) {
		oauth2.WriteError(w, oauth2.AccessDenied(req.State, oauth2.NoDescription))
		return
	}

	// check scope
	if !allowedScope.Includes(req.Scope) {
		oauth2.WriteError(w, oauth2.InvalidScope(req.State, oauth2.NoDescription))
		return
	}

	// issue access and refresh token
	at, rt, res := createTokensAndResponse(req)

	// save tokens
	saveTokens(at, rt, req.Scope, req.ClientID, req.Username)

	// write response
	oauth2.WriteTokenResponse(w, res)
}

func handleClientCredentialsGrant(w http.ResponseWriter, req *oauth2.TokenRequest) {
	// check scope
	if !allowedScope.Includes(req.Scope) {
		oauth2.WriteError(w, oauth2.InvalidScope(req.State, oauth2.NoDescription))
		return
	}

	// issue access and refresh token
	at, rt, res := createTokensAndResponse(req)

	// save tokens
	saveTokens(at, rt, req.Scope, req.ClientID, "")

	// write response
	oauth2.WriteTokenResponse(w, res)
}

func handleAuthorizationCodeGrant(w http.ResponseWriter, req *oauth2.TokenRequest) {
	// parse authorization code
	authorizationCode, err := hmacsha.Parse(secret, req.Code)
	if err != nil {
		oauth2.WriteError(w, oauth2.InvalidRequest(req.State, err.Error()))
		return
	}

	// get stored authorization code by signature
	storedAuthorizationCode, found := authorizationCodes[authorizationCode.SignatureString()]
	if !found {
		oauth2.WriteError(w, oauth2.InvalidGrant(req.State, "Unknown authorization code"))
		return
	}

	// validate expiration
	if storedAuthorizationCode.expiresAt.Before(time.Now()) {
		oauth2.WriteError(w, oauth2.InvalidGrant(req.State, "Expired authorization code"))
		return
	}

	// validate ownership
	if storedAuthorizationCode.clientID != req.ClientID {
		oauth2.WriteError(w, oauth2.InvalidGrant(req.State, "Invalid authorization code ownership"))
		return
	}

	// validate redirect uri
	if storedAuthorizationCode.redirectURI != req.RedirectURI {
		oauth2.WriteError(w, oauth2.InvalidGrant(req.State, "Changed redirect uri"))
		return
	}

	// validate scope
	if !storedAuthorizationCode.scope.Includes(req.Scope) {
		oauth2.WriteError(w, oauth2.InvalidScope(req.State, "Scope exceeds the originally granted scope"))
		return
	}

	// issue new access and refresh token
	at, rt, res := createTokensAndResponse(req)

	// save tokens
	saveTokens(at, rt, req.Scope, req.ClientID, "")

	// delete used authorization code
	delete(authorizationCodes, authorizationCode.SignatureString())

	// write response
	oauth2.WriteTokenResponse(w, res)
}

func handleRefreshTokenGrant(w http.ResponseWriter, req *oauth2.TokenRequest) {
	// parse refresh token
	refreshToken, err := hmacsha.Parse(secret, req.RefreshToken)
	if err != nil {
		oauth2.WriteError(w, oauth2.InvalidRequest(req.State, err.Error()))
		return
	}

	// get stored refresh token by signature
	storedRefreshToken, found := refreshTokens[refreshToken.SignatureString()]
	if !found {
		oauth2.WriteError(w, oauth2.InvalidGrant(req.State, "Unknown refresh token"))
		return
	}

	// validate expiration
	if storedRefreshToken.expiresAt.Before(time.Now()) {
		oauth2.WriteError(w, oauth2.InvalidGrant(req.State, "Expired refresh token"))
		return
	}

	// validate ownership
	if storedRefreshToken.clientID != req.ClientID {
		oauth2.WriteError(w, oauth2.InvalidGrant(req.State, "Invalid refresh token ownership"))
		return
	}

	// inherit scope from stored refresh token
	if req.Scope.Empty() {
		req.Scope = storedRefreshToken.scope
	}

	// validate scope - a missing scope is always included
	if !storedRefreshToken.scope.Includes(req.Scope) {
		oauth2.WriteError(w, oauth2.InvalidScope(req.State, "Scope exceeds the originally granted scope"))
		return
	}

	// issue new access and refresh token
	at, rt, res := createTokensAndResponse(req)

	// save tokens
	saveTokens(at, rt, req.Scope, req.ClientID, storedRefreshToken.username)

	// delete used refresh token
	delete(refreshTokens, refreshToken.SignatureString())

	// write response
	oauth2.WriteTokenResponse(w, res)
}

func createTokensAndResponse(req *oauth2.TokenRequest) (*hmacsha.Token, *hmacsha.Token, *oauth2.TokenResponse) {
	// generate new access token
	accessToken := hmacsha.MustGenerate(secret, 32)

	// generate new refresh token
	refreshToken := hmacsha.MustGenerate(secret, 32)

	// prepare response
	res := bearer.NewTokenResponse(accessToken.String(), int(tokenLifespan/time.Second))

	// set granted scope
	res.Scope = req.Scope

	// carry over state
	res.State = req.State

	// set refresh token
	res.RefreshToken = refreshToken.String()

	return accessToken, refreshToken, res
}

func saveTokens(accessToken, refreshToken *hmacsha.Token, scope oauth2.Scope, clientID, username string) {
	// save access token
	accessTokens[accessToken.SignatureString()] = token{
		clientID:  clientID,
		username:  username,
		signature: accessToken.SignatureString(),
		expiresAt: time.Now().Add(tokenLifespan),
		scope:     scope,
	}

	// save refresh token
	refreshTokens[refreshToken.SignatureString()] = token{
		clientID:  clientID,
		username:  username,
		signature: refreshToken.SignatureString(),
		expiresAt: time.Now().Add(tokenLifespan),
		scope:     scope,
	}
}