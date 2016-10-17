package main

import (
	"net/http"
	"time"

	"github.com/gonfire/oauth2"
)

func tokenEndpoint(w http.ResponseWriter, r *http.Request) {
	// parse token request
	req, err := oauth2.ParseAccessTokenRequest(r)
	if err != nil {
		oauth2.WriteError(w, err)
		return
	}

	// validate token request
	err = req.Validate()
	if err != nil {
		oauth2.WriteError(w, err)
		return
	}

	// check if client is confidential
	if !req.Confidential() {
		oauth2.WriteError(w, oauth2.InvalidRequest(req.State, "Only cofidential clients are allowed"))
		return
	}

	// authenticate client
	client, found := clients[req.ClientID]
	if !found || !sameHash(client.secret, req.ClientSecret) {
		oauth2.WriteError(w, oauth2.InvalidClient(req.State, oauth2.NoDescription))
		return
	}

	// triage grant type
	if req.GrantType.Password() {
		handleResourceOwnerPasswordCredentialsGrant(w, req)
	} else if req.GrantType.ClientCredentials() {
		handleClientCredentialsGrant(w, req)
	} else if req.GrantType.AuthorizationCode() {
		handleAuthorizationCodeGrant(w, req)
	} else if req.GrantType.RefreshToken() {
		handleRefreshTokenGrant(w, req)
	}
}

func handleResourceOwnerPasswordCredentialsGrant(w http.ResponseWriter, req *oauth2.AccessTokenRequest) {
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

func handleClientCredentialsGrant(w http.ResponseWriter, req *oauth2.AccessTokenRequest) {
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

func handleAuthorizationCodeGrant(w http.ResponseWriter, req *oauth2.AccessTokenRequest) {
	// parse authorization code
	authorizationCode, err := oauth2.ParseToken(secret, req.Code)
	if err != nil {
		oauth2.AddStateToError(err, req.State)
		oauth2.WriteError(w, err)
		return
	}

	// get stored authorization code by signature
	storedAuthorizationCode, found := authorizationCodes[authorizationCode.SignatureString()]
	if !found {
		oauth2.WriteError(w, oauth2.InvalidRequest(req.State, oauth2.NoDescription)) // TODO: Correct error?
		return
	}

	// validate ownership
	if storedAuthorizationCode.clientID != req.ClientID {
		oauth2.WriteError(w, oauth2.InvalidRequest(req.State, oauth2.NoDescription)) // TODO: Correct error?
		return
	}

	// validate scope and expiration
	if !storedAuthorizationCode.scope.Includes(req.Scope) || storedAuthorizationCode.expiresAt.Before(time.Now()) {
		oauth2.WriteError(w, oauth2.InvalidRequest(req.State, oauth2.NoDescription)) // TODO: Correct error?
		return
	}

	// validate redirect uri
	if req.RedirectURI != "" {
		if storedAuthorizationCode.redirectURI != req.RedirectURI {
			oauth2.WriteError(w, oauth2.InvalidRequest(req.State, oauth2.NoDescription)) // TODO: Correct error?
		}
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

func handleRefreshTokenGrant(w http.ResponseWriter, req *oauth2.AccessTokenRequest) {
	// parse refresh token
	refreshToken, err := oauth2.ParseToken(secret, req.RefreshToken)
	if err != nil {
		oauth2.AddStateToError(err, req.State)
		oauth2.WriteError(w, err)
		return
	}

	// get stored refresh token by signature
	storedRefreshToken, found := refreshTokens[refreshToken.SignatureString()]
	if !found {
		oauth2.WriteError(w, oauth2.InvalidGrant(req.State, oauth2.NoDescription))
		return
	}

	// validate ownership
	if storedRefreshToken.clientID != req.ClientID {
		oauth2.WriteError(w, oauth2.InvalidGrant(req.State, oauth2.NoDescription))
		return
	}

	// validate scope and expiration
	if !storedRefreshToken.scope.Includes(req.Scope) || storedRefreshToken.expiresAt.Before(time.Now()) {
		oauth2.WriteError(w, oauth2.InvalidGrant(req.State, oauth2.NoDescription))
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

func createTokensAndResponse(req *oauth2.AccessTokenRequest) (*oauth2.Token, *oauth2.Token, *oauth2.TokenResponse) {
	// generate new access token
	accessToken, err := oauth2.GenerateToken(secret, 32)
	if err != nil {
		panic(err)
	}

	// generate new refresh token
	refreshToken, err := oauth2.GenerateToken(secret, 32)
	if err != nil {
		panic(err)
	}

	// prepare response
	res := oauth2.NewBearerTokenResponse(accessToken.String(), int(tokenLifespan/time.Second))

	// set granted scope
	res.Scope = req.Scope

	// set refresh token
	res.RefreshToken = refreshToken.String()

	return accessToken, refreshToken, res
}

func saveTokens(accessToken, refreshToken *oauth2.Token, scope oauth2.Scope, clientID, username string) {
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
