package main

import (
	"net/http"
	"time"

	"github.com/gonfire/oauth2"
	"github.com/gonfire/oauth2/bearer"
)

var secret = []byte("abcd1234abcd1234")

var tokenLifespan = time.Hour

var authorizationCodeLifespan = 10 * time.Minute

var allowedScope = oauth2.ParseScope("foo bar")

func newHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", tokenEndpoint)
	mux.HandleFunc("/oauth2/authorize", authorizationEndpoint)
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
	tk, res := bearer.ParseToken(r)
	if res != nil {
		bearer.WriteError(w, res)
		return
	}

	// parse token
	token, err := oauth2.ParseToken(secret, tk)
	if err != nil {
		bearer.WriteError(w, bearer.InvalidToken("Malformed token"))
		return
	}

	// get token
	accessToken, found := accessTokens[token.SignatureString()]
	if !found {
		bearer.WriteError(w, bearer.InvalidToken("Unkown token"))
		return
	}

	// validate expiration
	if accessToken.expiresAt.Before(time.Now()) {
		bearer.WriteError(w, bearer.InvalidToken("Expired token"))
		return
	}

	// validate scope
	if !allowedScope.Includes(accessToken.scope) {
		bearer.WriteError(w, bearer.InsufficientScope(allowedScope.String()))
		return
	}

	w.Write([]byte("OK"))
}
