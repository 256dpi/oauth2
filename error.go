package oauth2

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type ErrorCode struct {
	Name   string
	Status int
}

func (c ErrorCode) String() string {
	return c.Name
}

func (c ErrorCode) MarshalJSON() ([]byte, error) {
	return json.Marshal(c.Name)
}

var (
	// The request is missing a required parameter, includes an invalid
	// parameter value, includes a parameter more than once, or is otherwise
	// malformed.
	InvalidRequest = ErrorCode{"invalid_request", http.StatusBadRequest}

	// Client authentication failed (e.g., unknown client, no client
	// authentication included, or unsupported authentication method).
	InvalidClient = ErrorCode{"invalid_client", http.StatusUnauthorized}
	// TODO: Status code is not always unauthorized?

	// The provided authorization grant (e.g., authorization code, resource
	// owner credentials) or refresh token is invalid, expired, revoked, does
	// not match the redirection URI used in the authorization request, or was
	// issued to another client.
	InvalidGrant = ErrorCode{"invalid_grant", http.StatusBadRequest}

	// The requested scope is invalid, unknown, malformed, or exceeds the scope
	// granted by the resource owner.
	InvalidScope = ErrorCode{"invalid_scope", http.StatusBadRequest}

	// The authenticated client is not authorized to use this authorization
	// grant type or method to request and access token.
	UnauthorizedClient = ErrorCode{"unauthorized_client", http.StatusUnauthorized}

	// The authorization grant type is not supported by the authorization server.
	UnsupportedGrantType = ErrorCode{"unsupported_grant_type", http.StatusBadRequest}

	// The authorization server does not support obtaining an access token using
	// this method.
	UnsupportedResponseType = ErrorCode{"unsupported_response_type", http.StatusBadRequest}

	// The resource owner or authorization server denied the request.
	AccessDenied = ErrorCode{"access_denied", http.StatusForbidden}
	// TODO: Correct status code?

	// The authorization server encountered an unexpected condition that
	// prevented it from fulfilling the request.
	ServerError = ErrorCode{"server_error", http.StatusInternalServerError}

	// The authorization server is currently unable to handle the request due
	// to a temporary overloading or maintenance of the server.
	TemporarilyUnavailable = ErrorCode{"temporarily_unavailable", http.StatusServiceUnavailable}
)

type Error struct {
	Code        ErrorCode         `json:"error"`
	Description string            `json:"error_description,omitempty"`
	URI         string            `json:"error_uri,omitempty"`
	State       string            `json:"state,omitempty"`
	ExtraFields map[string]string `json:",inline"`
}

func ErrorWithCode(code ErrorCode, description ...string) error {
	// get optional description
	desc := ""
	if len(description) > 0 {
		desc = description[0]
	}

	return &Error{
		Code:        code,
		Description: desc,
	}
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
	m["error"] = e.Code.Name

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

	// add extra fields
	for k, v := range e.ExtraFields {
		m[k] = v
	}

	return m
}

func WriteError(w http.ResponseWriter, err error) error {
	// ensure complex error
	anError, ok := err.(*Error)
	if !ok {
		anError = ErrorWithCode(ServerError).(*Error)
	}

	// write error response
	return WriteJSON(w, anError, anError.Code.Status)
}

func WriteErrorWithCode(w http.ResponseWriter, code ErrorCode, description ...string) error {
	return WriteError(w, ErrorWithCode(code, description...))
}

func WriteErrorRedirect(w http.ResponseWriter, uri string, err error, useFragment bool) error {
	// ensure complex error
	anError, ok := err.(*Error)
	if !ok {
		anError = ErrorWithCode(ServerError).(*Error)
	}

	// write redirect
	return WriteRedirect(w, uri, anError.Map(), useFragment)
}

func WriteErrorRedirectWithCode(w http.ResponseWriter, uri string, useFragment bool, code ErrorCode, description ...string) error {
	return WriteErrorRedirect(w, uri, ErrorWithCode(code, description...), useFragment)
}
