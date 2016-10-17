package oauth2

import (
	"fmt"
	"net/http"
)

const (
	NoState       = ""
	NoDescription = ""
)

type Error struct {
	Name        string `json:"error"`
	State       string `json:"state,omitempty"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"error_uri,omitempty"`

	Status  int               `json:"-"`
	Headers map[string]string `json:"-"`
}

func (e *Error) String() string {
	return fmt.Sprintf("%s: %s", e.Name, e.Description)
}

func (e *Error) Error() string {
	return e.String()
}

func (e *Error) Map() map[string]string {
	m := make(map[string]string)

	// add name
	m["error"] = e.Name

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
func InvalidRequest(state, description string) *Error {
	return &Error{
		Status:      http.StatusBadRequest,
		Name:        "invalid_request",
		State:       state,
		Description: description,
	}
}

// Client authentication failed (e.g., unknown client, no client
// authentication included, or unsupported authentication method).
func InvalidClient(state, description string) *Error {
	return &Error{
		Status:      http.StatusUnauthorized,
		Name:        "invalid_client",
		State:       state,
		Description: description,
		Headers: map[string]string{
			"WWW-Authenticate": `Basic realm="OAuth2"`,
		},
	}
}

// The provided authorization grant (e.g., authorization code, resource
// owner credentials) or refresh token is invalid, expired, revoked, does
// not match the redirection URI used in the authorization request, or was
// issued to another client.
func InvalidGrant(state, description string) *Error {
	return &Error{
		Status:      http.StatusBadRequest,
		Name:        "invalid_grant",
		State:       state,
		Description: description,
	}
}

// The requested scope is invalid, unknown, malformed, or exceeds the scope
// granted by the resource owner.
func InvalidScope(state, description string) *Error {
	return &Error{
		Status:      http.StatusBadRequest,
		Name:        "invalid_scope",
		State:       state,
		Description: description,
	}
}

// The authenticated client is not authorized to use this authorization
// grant type or method to request and access token.
func UnauthorizedClient(state, description string) *Error {
	return &Error{
		Status:      http.StatusBadRequest,
		Name:        "unauthorized_client",
		State:       state,
		Description: description,
	}
}

// The authorization grant type is not supported by the authorization server.
func UnsupportedGrantType(state, description string) *Error {
	return &Error{
		Status:      http.StatusBadRequest,
		Name:        "unsupported_grant_type",
		State:       state,
		Description: description,
	}
}

// The authorization server does not support obtaining an access token using
// this method.
func UnsupportedResponseType(state, description string) *Error {
	return &Error{
		Status:      http.StatusBadRequest,
		Name:        "unsupported_response_type",
		State:       state,
		Description: description,
	}
}

// The resource owner or authorization server denied the request.
func AccessDenied(state, description string) *Error {
	return &Error{
		Status:      http.StatusForbidden,
		Name:        "access_denied",
		State:       state,
		Description: description,
	}
}

// The authorization server encountered an unexpected condition that
// prevented it from fulfilling the request.
func ServerError(state, description string) *Error {
	return &Error{
		Status:      http.StatusInternalServerError,
		Name:        "server_error",
		State:       state,
		Description: description,
	}
}

// The authorization server is currently unable to handle the request due
// to a temporary overloading or maintenance of the server.
func TemporarilyUnavailable(state, description string) *Error {
	return &Error{
		Status:      http.StatusServiceUnavailable,
		Name:        "temporarily_unavailable",
		State:       state,
		Description: description,
	}
}

func AddStateToError(err error, state string) {
	if anError, ok := err.(*Error); ok {
		anError.State = state
	}
}

func WriteError(w http.ResponseWriter, err error) error {
	// ensure complex error
	anError, ok := err.(*Error)
	if !ok {
		anError = ServerError(NoState, NoDescription)
	}

	// add headers
	for k, v := range anError.Headers {
		w.Header().Set(k, v)
	}

	// write error response
	return Write(w, anError, anError.Status)
}

func RedirectError(w http.ResponseWriter, uri string, useFragment bool, err error) error {
	// ensure complex error
	anError, ok := err.(*Error)
	if !ok {
		anError = ServerError(NoState, NoDescription)
	}

	// write redirect
	return Redirect(w, uri, anError.Map(), useFragment)
}
