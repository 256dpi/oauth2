package bearer

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/gonfire/oauth2"
	"sort"
)

// TokenType is the bearer token type as defined by the OAuth2 Bearer Token spec.
const TokenType = "bearer"

// NewTokenResponse creates and returns a new token response that carries
// a bearer token.
func NewTokenResponse(token string, expiresIn int) *oauth2.TokenResponse {
	return oauth2.NewTokenResponse(TokenType, token, expiresIn)
}

// An Error represents an unsuccessful bearer token authentication.
type Error struct {
	Name        string
	Description string
	URI         string
	Realm       string
	Scope       string
	Status      int
}

// Map returns a map of all fields that can be presented to the client.
func (e *Error) Map() map[string]string {
	m := make(map[string]string)

	// add name
	m["error"] = e.Name

	// add description if present
	if e.Description != "" {
		m["error_description"] = e.Description
	}

	// add uri if present
	if e.URI != "" {
		m["error_uri"] = e.URI
	}

	// add realm if present
	if e.Realm != "" {
		m["realm"] = e.Realm
	}

	// add scope if present
	if e.Scope != "" {
		m["scope"] = e.Scope
	}

	return m
}

// Params returns an encoded representation of the error parameters.
func (e *Error) Params() string {
	// prepare params
	var params []string

	// add all params
	for k, v := range e.Map() {
		params = append(params, fmt.Sprintf(`%s="%s"`, k, v))
	}

	// sort params
	sort.Strings(params)

	return strings.Join(params, ", ")
}

// Error implements the error interface.
func (e *Error) Error() string {
	return fmt.Sprintf("%s: %s", e.Name, e.Description)
}

// InvalidRequest constructs and error that indicates that the request is
// missing a required parameter, includes an unsupported parameter or parameter
// value, repeats the same parameter, uses more than one method for including an
// access token, or is otherwise malformed.
func InvalidRequest(description string) *Error {
	return &Error{
		Name:        "invalid_request",
		Description: description,
		Status:      http.StatusBadRequest,
	}
}

// InvalidToken constructs and error that indicates that the access token
// provided is expired, revoked, malformed, or invalid for
// other reasons.
func InvalidToken(description string) *Error {
	return &Error{
		Name:        "invalid_token",
		Description: description,
		Status:      http.StatusUnauthorized,
	}
}

// InsufficientScope constructs and error that indicates that the request
// requires higher privileges than provided by the access token.
func InsufficientScope(necessaryScope string) *Error {
	return &Error{
		Name:   "insufficient_scope",
		Scope:  necessaryScope,
		Status: http.StatusForbidden,
	}
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

	// split header
	s := strings.SplitN(h, " ", 2)
	if len(s) != 2 || !strings.EqualFold(s[0], TokenType) {
		return "", InvalidRequest("Malformed authorization header")
	}

	return s[1], nil
}

// WriteError will write the specified error to the response writer. The function
// will fall back and write an internal server error if the specified error is
// not known.
func WriteError(w http.ResponseWriter, err error) error {
	// ensure complex error
	anError, ok := err.(*Error)
	if !ok {
		// write internal server error
		w.WriteHeader(http.StatusInternalServerError)

		// finish response
		_, err = w.Write(nil)

		return err
	}

	// prepare response
	response := "Bearer " + anError.Params()

	// set header
	w.Header().Set("WWW-Authenticate", response)

	// write header
	w.WriteHeader(anError.Status)

	// finish response
	_, err = w.Write(nil)

	return err
}
