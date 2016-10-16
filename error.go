package oauth2

import (
	"fmt"
	"net/http"
)

type Error struct {
	Status      int    `json:"-"`
	Code        string `json:"error"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"error_uri,omitempty"`
	State       string `json:"state,omitempty"`
}

func (e *Error) String() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Description)
}

func (e *Error) Error() string {
	return e.String()
}

func (e *Error) Map() map[string]string {
	m := make(map[string]string)

	// add name
	m["error"] = e.Code

	// add description
	if len(e.Description) > 0 {
		m["error_description"] = e.Description
	}

	// add state
	if len(e.State) > 0 {
		m["state"] = e.State
	}

	// add uri
	if len(e.URI) > 0 {
		m["error_uri"] = e.URI
	}

	return m
}

// The request is missing a required parameter, includes an invalid
// parameter value, includes a parameter more than once, or is otherwise
// malformed.
func InvalidRequest(description string) *Error {
	return &Error{
		Status:      http.StatusBadRequest,
		Code:        "invalid_request",
		Description: description,
	}
}

// Client authentication failed (e.g., unknown client, no client
// authentication included, or unsupported authentication method).
func InvalidClient(description string) *Error {
	// TODO: Status code is not always unauthorized?
	// TODO: How to return "WWW-Authenticate" header?

	return &Error{
		Status:      http.StatusUnauthorized,
		Code:        "invalid_client",
		Description: description,
	}
}

// The provided authorization grant (e.g., authorization code, resource
// owner credentials) or refresh token is invalid, expired, revoked, does
// not match the redirection URI used in the authorization request, or was
// issued to another client.
func InvalidGrant(description string) *Error {
	return &Error{
		Status:      http.StatusBadRequest,
		Code:        "invalid_grant",
		Description: description,
	}
}

// The requested scope is invalid, unknown, malformed, or exceeds the scope
// granted by the resource owner.
func InvalidScope(description string) *Error {
	return &Error{
		Status:      http.StatusBadRequest,
		Code:        "invalid_scope",
		Description: description,
	}
}

// The authenticated client is not authorized to use this authorization
// grant type or method to request and access token.
func UnauthorizedClient(description string) *Error {
	return &Error{
		Status:      http.StatusBadRequest,
		Code:        "unauthorized_client",
		Description: description,
	}
}

// The authorization grant type is not supported by the authorization server.
func UnsupportedGrantType(description string) *Error {
	return &Error{
		Status:      http.StatusBadRequest,
		Code:        "unsupported_grant_type",
		Description: description,
	}
}

// The authorization server does not support obtaining an access token using
// this method.
func UnsupportedResponseType(description string) *Error {
	return &Error{
		Status:      http.StatusBadRequest,
		Code:        "unsupported_response_type",
		Description: description,
	}
}

// The resource owner or authorization server denied the request.
func AccessDenied(description string) *Error {
	return &Error{
		Status:      http.StatusForbidden,
		Code:        "access_denied",
		Description: description,
	}
}

// The authorization server encountered an unexpected condition that
// prevented it from fulfilling the request.
func ServerError(description string) *Error {
	return &Error{
		Status:      http.StatusInternalServerError,
		Code:        "server_error",
		Description: description,
	}
}

// The authorization server is currently unable to handle the request due
// to a temporary overloading or maintenance of the server.
func TemporarilyUnavailable(description string) *Error {
	return &Error{
		Status:      http.StatusServiceUnavailable,
		Code:        "temporarily_unavailable",
		Description: description,
	}
}

func WriteError(w http.ResponseWriter, err error) error {
	// ensure complex error
	anError, ok := err.(*Error)
	if !ok {
		anError = ServerError("")
	}

	// write error response
	return Write(w, anError, anError.Status)
}

func WriteErrorRedirect(w http.ResponseWriter, uri string, useFragment bool, err error) error {
	// ensure complex error
	anError, ok := err.(*Error)
	if !ok {
		anError = ServerError("")
	}

	// write redirect
	return WriteRedirect(w, uri, anError.Map(), useFragment)
}
