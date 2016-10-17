package oauth2

import (
	"net/http"
	"strings"
)

const Bearer = "bearer"

func NewBearerTokenResponse(accessToken string, expiresIn int) *TokenResponse {
	return NewTokenResponse(Bearer, accessToken, expiresIn)
}

func ParseBearerToken(r *http.Request) (string, error) {
	// read header
	h := r.Header.Get("Authorization")

	// split header
	s := strings.SplitN(h, " ", 2)
	if len(s) != 2 || !strings.EqualFold(s[0], Bearer) {
		return "", InvalidRequest(NoState, "Malformed or missing authorization header")
	}

	return s[1], nil
}
