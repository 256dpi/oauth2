package oauth2

import (
	"errors"
	"net/http"
	"strings"
)

// The bearer token type.
const BearerTokenType = "bearer"

// NewBearerTokenResponse creates and returns a new token response that carries
// a bearer token.
func NewBearerTokenResponse(token string, expiresIn int) *TokenResponse {
	return NewTokenResponse(BearerTokenType, token, expiresIn)
}

// ParseBearerToken parses and returns the bearer token from a request. It will
// return standard errors if the extraction failed.
//
// Note: The spec also allows obtaining the bearer token from query parameters
// and the request body (form data). This implementation only supports obtaining
// the token from the "Authorization" header as this is the most common use case
// and considered most secure.
func ParseBearerToken(r *http.Request) (string, error) {
	// read header
	h := r.Header.Get("Authorization")

	// split header
	s := strings.SplitN(h, " ", 2)
	if len(s) != 2 || !strings.EqualFold(s[0], BearerTokenType) {
		return "", errors.New("Malformed or missing authorization header")
	}

	// TODO: Implement "WWW-Authenticate" header in response: https://tools.ietf.org/html/rfc6750#section-3.

	return s[1], nil
}
