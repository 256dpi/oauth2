// Package bearer provides structures and functions to implement the additional
// OAuth2 Bearer Token specification.
package bearer

import (
	"net/http"
	"strings"

	"github.com/256dpi/oauth2"
)

// TokenType is the bearer token type as defined by the OAuth2 Bearer Token spec.
const TokenType = "bearer"

// NewTokenResponse creates and returns a new token response that carries
// a bearer token.
func NewTokenResponse(token string, expiresIn int) *oauth2.TokenResponse {
	return oauth2.NewTokenResponse(TokenType, token, expiresIn)
}

// ParseToken parses and returns the bearer token from a request. It will
// return an Error instance if the extraction failed.
//
// Note: The spec also allows obtaining the bearer token from query parameters
// and the request body (form data). This implementation only supports obtaining
// the token from the "Authorization" header as this is the most common use case
// and considered most secure.
func ParseToken(r *http.Request) (string, error) {
	// read header
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", ProtectedResource()
	}

	// split header
	s := strings.SplitN(h, " ", 2)
	if len(s) != 2 || !strings.EqualFold(s[0], TokenType) {
		return "", InvalidRequest("malformed authorization header")
	}

	return s[1], nil
}
