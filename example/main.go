package main

import (
	"net/http"

	"github.com/gonfire/oauth2"
)

var secret = []byte("abcd1234abcd1234")

func main() {
	// add endpoints
	http.HandleFunc("/oauth2/token", tokenEndpoint)
	http.HandleFunc("/oauth2/authorize", authorizeEndpoint)

	// run server
	http.ListenAndServe("0.0.0.0:4000", nil)
}

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
