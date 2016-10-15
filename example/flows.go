package main

import (
	"net/http"
	"time"

	"github.com/gonfire/oauth2"
)

func tokenEndpoint(w http.ResponseWriter, r *http.Request) {
	// parse oauth2 token request
	req, err := oauth2.ParseAccessRequest(r)
	if err != nil {
		oauth2.WriteError(w, err)
		return
	}

	// check if client is confidential
	if !req.Confidential() {
		oauth2.WriteErrorWithCode(w, oauth2.InvalidRequest, "Only cofidential clients are allowed")
		return
	}

	// authenticate client
	hash, found := clients[req.ClientID]
	if !found || !sameHash(hash, req.ClientSecret) {
		oauth2.WriteErrorWithCode(w, oauth2.InvalidClient)
		return
	}

	// triage grant type
	if req.GrantType.Password() {
		handlePasswordFlow(w, req)
	} else if req.GrantType.ClientCredentials() {
		handleClientCredentialsFlow(w, req)
	} else if req.GrantType.AuthorizationCode() {
		//TODO: handleAuthorizationCodeGrant(w, r, req)
	} else if req.GrantType.RefreshToken() {
		handleRefreshTokenFlow(w, req)
	} else {
		oauth2.WriteError(w, oauth2.ErrorWithCode(oauth2.UnsupportedGrantType))
	}
}

func handlePasswordFlow(w http.ResponseWriter, req *oauth2.AccessRequest) {
	// authenticate resource owner
	hash, found := users[req.Username]
	if !found || !sameHash(hash, req.Password) {
		oauth2.WriteErrorWithCode(w, oauth2.AccessDenied)
		return
	}

	// check scope
	if req.Scope != "foo" {
		oauth2.WriteErrorWithCode(w, oauth2.InvalidScope)
		return
	}

	// issue access and refresh token
	at, rt, res := createTokensAndResponse(req)

	// save tokens
	saveTokens(at, rt, req.ClientID, req.Username)

	// write response
	oauth2.WriteResponse(w, res)
}

func handleClientCredentialsFlow(w http.ResponseWriter, req *oauth2.AccessRequest) {
	// check scope
	if req.Scope != "foo" {
		oauth2.WriteErrorWithCode(w, oauth2.InvalidScope)
		return
	}

	// issue access and refresh token
	at, rt, res := createTokensAndResponse(req)

	// save tokens
	saveTokens(at, rt, req.ClientID, "")

	// write response
	oauth2.WriteResponse(w, res)
}

func handleRefreshTokenFlow(w http.ResponseWriter, req *oauth2.AccessRequest) {
	// parse refresh token
	refreshToken, err := oauth2.ParseToken(secret, req.RefreshToken)
	if err != nil {
		oauth2.WriteError(w, err)
		return
	}

	// get stored refresh token by signature
	storedRefreshToken, found := refreshTokens[refreshToken.Signature]
	if !found {
		oauth2.WriteErrorWithCode(w, oauth2.InvalidRequest) // TODO: ok?
		return
	}

	// validate ownership
	if storedRefreshToken.clientID != req.ClientID || storedRefreshToken.username != req.Username {
		oauth2.WriteErrorWithCode(w, oauth2.InvalidRequest) // TODO: ok?
		return
	}

	// validate expiration
	if storedRefreshToken.expiresAt.Before(time.Now()) {
		oauth2.WriteErrorWithCode(w, oauth2.InvalidRequest) // TODO: ok?
		return
	}

	// TODO: Validate scopes to match.

	// issue new access and refresh token
	at, rt, res := createTokensAndResponse(req)

	// save tokens
	saveTokens(at, rt, storedRefreshToken.clientID, storedRefreshToken.username)

	// write response
	oauth2.WriteResponse(w, res)
}

func createTokensAndResponse(req *oauth2.AccessRequest) (*oauth2.Token, *oauth2.Token, *oauth2.Response) {
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
	res := oauth2.NewBearerTokenResponse(accessToken, 3600)

	// set granted scopes
	res.Scope = req.Scope

	// set refresh token
	res.RefreshToken = refreshToken

	return accessToken, refreshToken, res
}

func saveTokens(accessToken, refreshToken *oauth2.Token, clientID, username string) {
	// save access token
	accessTokens[accessToken.SignatureString()] = token{
		clientID:  clientID,
		username:  username,
		signature: accessToken.SignatureString(),
		expiresAt: time.Now().Add(time.Hour),
	}

	// save refresh token
	refreshTokens[refreshToken.SignatureString()] = token{
		clientID:  clientID,
		username:  username,
		signature: refreshToken.SignatureString(),
		expiresAt: time.Now().Add(time.Hour),
	}
}
