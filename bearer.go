package oauth2

import (
	"net/http"
	"strings"
)

const Bearer = "bearer"

func NewBearerTokenResponse(accessToken string, expiresIn int) *TokenResponse {
	return NewTokenResponse(Bearer, accessToken, expiresIn)
}

func ParseBearerToken(secret []byte, r *http.Request) (*Token, error) {
	// read header
	h := r.Header.Get("Authorization")

	// split header
	s := strings.SplitN(h, " ", 2)
	if len(s) != 2 || !strings.EqualFold(s[0], Bearer) {
		return nil, InvalidRequest(NoState, "Malformed or missing authorization header")
	}

	// parse extracted token
	return ParseToken(secret, s[1])
}
