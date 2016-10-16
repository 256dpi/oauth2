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

func newHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", tokenEndpoint)
	mux.HandleFunc("/oauth2/authorize", authorizeEndpoint)
	mux.HandleFunc("/api/protected", protectedResource)
	return mux
}

func main() {
	// create server
	server := http.Server{
		Addr:    "0.0.0.0:4000",
		Handler: newHandler(),
	}

	// run server
	server.ListenAndServe()
}

func protectedResource(w http.ResponseWriter, r *http.Request) {
	// parse bearer token
	token, err := oauth2.ParseBearerToken(secret, r)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// validate access token
	accessToken, found := accessTokens[token.SignatureString()]
	if !found || accessToken.expiresAt.Before(time.Now()) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	w.Write([]byte("OK"))
}
