package oauth2

import (
	"net/http"
	"strings"
)

const Bearer = "bearer"

func NewBearerTokenResponse(token string, expiresIn int) *TokenResponse {
	return NewTokenResponse(Bearer, token, expiresIn)
}

// Note: The spec also allows obtaining the bearer token from query parameters
// and the request body (form data). This implementations only supports obtaining
// the token from the "Authorization" header as this is the most common
// implementation and considered most secure.
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

// TODO: Implement "WWW-Authenticate" header in response: https://tools.ietf.org/html/rfc6750#section-3.
