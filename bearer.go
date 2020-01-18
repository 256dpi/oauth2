package oauth2

import (
	"net/http"
	"strings"
)

// BearerTokenType is the bearer token type as defined by the OAuth2 Bearer
// Token spec.
const BearerTokenType = "bearer"

// NewBearerTokenResponse creates and returns a new token response that carries
// a bearer token.
func NewBearerTokenResponse(token string, expiresIn int) *TokenResponse {
	return NewTokenResponse(BearerTokenType, token, expiresIn)
}

// ParseBearerToken parses and returns the bearer token from a request. It will
// return an BearerError instance if the extraction failed.
//
// Note: The spec also allows obtaining the bearer token from query parameters
// and the request body (form data). This implementation only supports obtaining
// the token from the "Authorization" header as this is the most common use case
// and considered most secure.
func ParseBearerToken(r *http.Request) (string, error) {
	// read header
	h := r.Header.Get("Authorization")
	if h == "" {
		return "", ProtectedResource()
	}

	// split header
	s := strings.SplitN(h, " ", 2)
	if len(s) != 2 || !strings.EqualFold(s[0], BearerTokenType) {
		return "", InvalidRequest("malformed authorization header")
	}

	return s[1], nil
}

// WriteBearerError will write the specified error to the response writer. The
// function will fall back and write an internal server error if the specified
// error is not known.
//
// Bearer Token Errors: ProtectedResource, InvalidRequest, InvalidToken,
// InsufficientScope, ServerError.
func WriteBearerError(w http.ResponseWriter, err error) error {
	// ensure complex error
	anError, ok := err.(*Error)
	if !ok || anError.Status == http.StatusInternalServerError {
		// write internal server error
		w.WriteHeader(http.StatusInternalServerError)

		// finish response
		_, err = w.Write(nil)

		return err
	}

	// get params
	params := anError.Params()

	// force at least one parameter
	if params == "" {
		params = `realm="OAuth2"`
	}

	// prepare response
	response := "Bearer " + params

	// set header
	w.Header().Set("WWW-Authenticate", response)

	// write header
	w.WriteHeader(anError.Status)

	// finish response
	_, err = w.Write(nil)

	return err
}
