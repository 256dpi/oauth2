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
		//handleExplicitFlow(w, req)
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

	// issue access
	at, res := createTokenAndResponse(req)

	// save tokens
	saveToken(at, req.Scope, req.ClientID, "")

	// set state
	res.State = req.State

	// write response
	oauth2.WriteResponseRedirect(w, res, req.RedirectURI)
}

func createTokenAndResponse(req *oauth2.AccessTokenRequest) (*oauth2.Token, *oauth2.Response) {
	// generate new access token
	accessToken, err := oauth2.GenerateToken(secret, 32)
	if err != nil {
		panic(err)
	}

	// prepare response
	res := oauth2.NewBearerTokenResponse(accessToken, tokenLifespan/time.Second)

	// set granted scope
	res.Scope = req.Scope

	return accessToken, res
}

func saveToken(accessToken *oauth2.Token, scope *oauth2.Scope, clientID, username string) {
	// save access token
	accessTokens[accessToken.SignatureString()] = token{
		clientID:  clientID,
		username:  username,
		signature: accessToken.SignatureString(),
		expiresAt: time.Now().Add(tokenLifespan),
		scope:     scope,
	}
}
