package oauth2

import (
	"net/http"
	"strings"
)

// BearerAccessTokenType is the bearer access token type as defined by the
// OAuth2 Bearer Token spec.
const BearerAccessTokenType = "bearer"

// NewBearerTokenResponse creates and returns a new token response that carries
// a bearer access token.
func NewBearerTokenResponse(token string, expiresIn int) *TokenResponse {
	return NewTokenResponse(BearerAccessTokenType, token, expiresIn)
}

// ParseBearerToken parses and returns the bearer token from a request. It will
// return an Error if the extraction failed.
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

	// check length
	if len(h) < len(BearerAccessTokenType)+2 {
		return "", InvalidRequest("malformed authorization header")
	}

	// check type
	if !strings.EqualFold(h[:len(BearerAccessTokenType)], BearerAccessTokenType) {
		return "", InvalidRequest("malformed authorization header")
	}

	// check space
	if h[len(BearerAccessTokenType):len(BearerAccessTokenType)+1] != " " {
		return "", InvalidRequest("malformed authorization header")
	}

	// get token
	token := h[len(BearerAccessTokenType)+1:]

	return token, nil
}

// WriteBearerError will write the specified error to the response writer. The
// function will fall back and write an internal server error if the specified
// error is not known.
//
// Common bearer token errors: ProtectedResource, InvalidRequest, InvalidToken,
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
