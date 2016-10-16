package main

import (
	"net/http"
	"time"

	"github.com/gonfire/oauth2"
)

func authorizeEndpoint(w http.ResponseWriter, r *http.Request) {
	// parse oauth2 authorization request
	req, err := oauth2.ParseAuthorizationRequest(r)
	if err != nil {
		oauth2.WriteError(w, err)
	}

	// get client
	client, found := clients[req.ClientID]
	if !found {
		oauth2.WriteErrorWithCode(w, oauth2.InvalidClient)
		return
	}

	// validate redirect uri
	if client.redirectURI != req.RedirectURI {
		oauth2.WriteErrorWithCode(w, oauth2.InvalidRequest, "Invalid redirect URI")
		return
	}

	// triage grant type
	if req.ResponseType.Token() {
		handleImplicitFlow(w, req)
	} else if req.ResponseType.Code() {
		handleAuthorizationCodeFlow(w, req)
	} else {
		oauth2.WriteError(w, oauth2.ErrorWithCode(oauth2.UnsupportedResponseType))
	}
}

func handleImplicitFlow(w http.ResponseWriter, req *oauth2.AuthorizationRequest) {
	// check scope
	if !allowedScope.Includes(req.Scope) {
		oauth2.WriteErrorRedirectWithCode(w, req.RedirectURI, oauth2.InvalidScope)
		return
	}

	// generate new access token
	accessToken, err := oauth2.GenerateToken(secret, 32)
	if err != nil {
		panic(err)
	}

	// prepare response
	res := oauth2.NewBearerTokenResponse(accessToken, tokenLifespan/time.Second)

	// set granted scope
	res.Scope = req.Scope

	// set state
	res.State = req.State

	// save access token
	accessTokens[accessToken.SignatureString()] = token{
		clientID:  req.ClientID,
		signature: accessToken.SignatureString(),
		expiresAt: time.Now().Add(tokenLifespan),
		scope:     req.Scope,
	}

	// write response
	oauth2.WriteResponseRedirect(w, res, req.RedirectURI)
}

func handleAuthorizationCodeFlow(w http.ResponseWriter, req *oauth2.AuthorizationRequest) {
	// check scope
	if !allowedScope.Includes(req.Scope) {
		oauth2.WriteErrorRedirectWithCode(w, req.RedirectURI, oauth2.InvalidScope)
		return
	}

	// generate new authorization code
	authorizationCode, err := oauth2.GenerateToken(secret, 32)
	if err != nil {
		panic(err)
	}

	// prepare response
	res := oauth2.NewAuthorizationCodeResponse(authorizationCode)

	// set state
	res.State = req.State

	// save authorization code
	authorizationCodes[authorizationCode.SignatureString()] = token{
		clientID:  req.ClientID,
		signature: authorizationCode.SignatureString(),
		expiresAt: time.Now().Add(authorizationCodeLifespan),
		scope:     req.Scope,
	}

	// write response
	oauth2.WriteResponseRedirect(w, res, req.RedirectURI)
}
