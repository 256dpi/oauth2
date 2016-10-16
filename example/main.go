package main

import (
	"net/http"
	"time"

	"github.com/gonfire/oauth2"
)

var secret = []byte("abcd1234abcd1234")

var tokenLifespan = time.Hour

var authorizationCodeLifespan = 10 * time.Minute

var allowedScope = oauth2.ParseScope("foo bar")

func main() {
	// add endpoints
	http.HandleFunc("/oauth2/token", tokenEndpoint)
	http.HandleFunc("/oauth2/authorize", authorizeEndpoint)

	// run server
	http.ListenAndServe("0.0.0.0:4000", nil)
}
