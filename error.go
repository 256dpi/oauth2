package oauth2

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"sort"
	"strings"
)

// An Error represents an error object defined by the OAuth2 specification. All
// functions that are used during the authorization and token request processing
// flow return such error instances.
type Error struct {
	Name        string `json:"error"`
	State       string `json:"state,omitempty"`
	Scope       string `json:"scope,omitempty"`
	Realm       string `json:"realm,omitempty"`
	Description string `json:"error_description,omitempty"`
	URI         string `json:"error_uri,omitempty"`

	Status      int               `json:"-"`
	Headers     map[string]string `json:"-"`
	RedirectURI string            `json:"-"`
	UseFragment bool              `json:"-"`
}

// SetRedirect marks the error to be redirected by setting the state value as
// well as the redirect URI and whether the error should be added to the query
// parameter or fragment part of the URI.
func (e *Error) SetRedirect(uri, state string, useFragment bool) *Error {
	e.State = state
	e.RedirectURI = uri
	e.UseFragment = useFragment

	return e
}

// String implements the fmt.Stringer interface.
func (e *Error) String() string {
	return fmt.Sprintf("%s: %s", e.Name, e.Description)
}

// Error implements the error interface.
func (e *Error) Error() string {
	return e.String()
}

// Map returns a map of all fields that can be presented to the client. This
// method can be used to construct query parameters or a fragment when
// redirecting the error.
func (e *Error) Map() map[string]string {
	m := make(map[string]string)

	// add name
	if e.Name != "" {
		m["error"] = e.Name
	}

	// add description
	if e.Description != "" {
		m["error_description"] = e.Description
	}

	// add state
	if e.State != "" {
		m["state"] = e.State
	}

	// add scope if present
	if e.Scope != "" {
		m["scope"] = e.Scope
	}

	// add uri
	if e.URI != "" {
		m["error_uri"] = e.URI
	}

	// add realm if present
	if e.Realm != "" {
		m["realm"] = e.Realm
	}

	return m
}

// Params returns an string encoded representation of the error parameters.
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

// InvalidRequest constructs an error that indicates that the request is missing
// a required parameter, includes an invalid parameter value, includes a parameter
// more than once, or is otherwise malformed.
func InvalidRequest(description string) *Error {
	return &Error{
		Status:      http.StatusBadRequest,
		Name:        "invalid_request",
		Description: description,
	}
}

// InvalidClient constructs an error that indicates that the client
// authentication failed (e.g., unknown client, no client authentication included,
// or unsupported authentication method).
func InvalidClient(description string) *Error {
	return &Error{
		Status:      http.StatusUnauthorized,
		Name:        "invalid_client",
		Description: description,
		Headers: map[string]string{
			"WWW-Authenticate": `Basic realm="OAuth2"`,
		},
	}
}

// InvalidGrant constructs an error that indicates that the provided
// authorization grant (e.g., authorization code, resource owner credentials) or
// refresh token is invalid, expired, revoked, does not match the redirection URI
// used in the authorization request, or was issued to another client.
func InvalidGrant(description string) *Error {
	return &Error{
		Status:      http.StatusBadRequest,
		Name:        "invalid_grant",
		Description: description,
	}
}

// InvalidScope constructs an error that indicates that the requested scope is
// invalid, unknown, malformed, or exceeds the scope granted by the resource owner.
func InvalidScope(description string) *Error {
	return &Error{
		Status:      http.StatusBadRequest,
		Name:        "invalid_scope",
		Description: description,
	}
}

// InvalidToken constructs and error that indicates that the access token
// provided is expired, revoked, malformed, or invalid for
// other reasons.
func InvalidToken(description string) *Error {
	return &Error{
		Status:      http.StatusUnauthorized,
		Name:        "invalid_token",
		Description: description,
	}
}

// UnauthorizedClient constructs an error that indicates that the authenticated
// client is not authorized to use this authorization grant type or method to
// request and access token.
func UnauthorizedClient(description string) *Error {
	return &Error{
		Status:      http.StatusBadRequest,
		Name:        "unauthorized_client",
		Description: description,
	}
}

// UnsupportedGrantType constructs an error that indicates that the authorization
// grant type is not supported by the authorization server.
func UnsupportedGrantType(description string) *Error {
	return &Error{
		Status:      http.StatusBadRequest,
		Name:        "unsupported_grant_type",
		Description: description,
	}
}

// UnsupportedResponseType constructs an error that indicates that the
// authorization server does not support obtaining an access token using this
// method.
func UnsupportedResponseType(description string) *Error {
	return &Error{
		Status:      http.StatusBadRequest,
		Name:        "unsupported_response_type",
		Description: description,
	}
}

// UnsupportedTokenType constructs an error that indicates that the authorization
// server does not support the introspection of the presented token type.
func UnsupportedTokenType(description string) *Error {
	return &Error{
		Status:      http.StatusBadRequest,
		Name:        "unsupported_token_type",
		Description: description,
	}
}

// ProtectedResource constructs and error that indicates that the requested
// resource needs authentication.
func ProtectedResource() *Error {
	return &Error{
		Status: http.StatusUnauthorized,
	}
}

// InsufficientScope constructs and error that indicates that the request
// requires higher privileges than provided by the access token.
func InsufficientScope(necessaryScope string) *Error {
	return &Error{
		Status: http.StatusForbidden,
		Name:   "insufficient_scope",
		Scope:  necessaryScope,
	}
}

// AccessDenied constructs an error that indicates that the resource owner or
// authorization server denied the request.
func AccessDenied(description string) *Error {
	return &Error{
		Status:      http.StatusForbidden,
		Name:        "access_denied",
		Description: description,
	}
}

// ServerError constructs an error that indicates that the authorization server
// encountered an unexpected condition that prevented it from fulfilling the
// request.
func ServerError(description string) *Error {
	return &Error{
		Status:      http.StatusInternalServerError,
		Name:        "server_error",
		Description: description,
	}
}

// TemporarilyUnavailable constructs an error that indicates that the
// authorization server is currently unable to handle the request due to a
// temporary overloading or maintenance of the server.
func TemporarilyUnavailable(description string) *Error {
	return &Error{
		Status:      http.StatusServiceUnavailable,
		Name:        "temporarily_unavailable",
		Description: description,
	}
}

// WriteError will write the specified error to the response writer. The function
// will fall back and write a server error if the specified error is not known.
// If the RedirectURI field is present on the error a redirection will be written
// instead.
func WriteError(w http.ResponseWriter, err error) error {
	// ensure complex error
	anError, ok := err.(*Error)
	if !ok {
		anError = ServerError("")
	}

	// add headers
	for k, v := range anError.Headers {
		w.Header().Set(k, v)
	}

	// redirect error if requested
	if anError.RedirectURI != "" {
		return WriteRedirect(w, anError.RedirectURI, anError.Map(), anError.UseFragment)
	}

	return Write(w, anError, anError.Status)
}

// ParseRequestError will try to parse an oauth2.Error from the provided
// response. It will fallback to an error containing the response status.
func ParseRequestError(res *http.Response, limit int64) error {
	// read full body
	data, _ := ioutil.ReadAll(io.LimitReader(res.Body, limit))

	// check oauth error
	var oauthError Error
	if json.Unmarshal(data, &oauthError) == nil {
		oauthError.Status = res.StatusCode
		return &oauthError
	}

	return fmt.Errorf("unexpected response: %s", res.Status)
}
