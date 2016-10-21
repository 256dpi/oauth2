package server

import (
	"net/http"
	"time"

	"github.com/gonfire/oauth2"
	"github.com/gonfire/oauth2/bearer"
	"github.com/gonfire/oauth2/hmacsha"
)

var secret = []byte("abcd1234abcd1234")

var tokenLifespan = time.Hour
var refreshTokenLifespan = 7 * 24 * time.Hour
var authorizationCodeLifespan = 10 * time.Minute

var allowedScope = oauth2.ParseScope("foo bar")
var requiredScope = oauth2.ParseScope("foo")

func newHandler(d *manager) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", tokenEndpoint(d))
	mux.HandleFunc("/oauth2/authorize", authorizationEndpoint(d))
	mux.HandleFunc("/api/protected", protectedResource)
	return mux
}

func protectedResource(w http.ResponseWriter, r *http.Request) {
	// parse bearer token
	tk, res := bearer.ParseToken(r)
	if res != nil {
		bearer.WriteError(w, res)
		return
	}

	// parse token
	token, err := hmacsha.Parse(secret, tk)
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
	if !accessToken.scope.Includes(requiredScope) {
		bearer.WriteError(w, bearer.InsufficientScope(requiredScope.String()))
		return
	}

	w.Write([]byte("OK"))
}
