package main

import (
	"net/http"

	"github.com/gonfire/oauth2"
)

func authorizeEndpoint(w http.ResponseWriter, r *http.Request) {
	req, err := oauth2.ParseAuthorizationRequest(r)
	if err != nil {
		oauth2.WriteError(w, err)
	}

	// TODO: Which errors to redirect and which to respond?

	// load client
	// compare client hashes
	// invoke flow
	// write response
}
