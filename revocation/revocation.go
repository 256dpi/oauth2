// Package revocation provides structures and functions to implement the
// additional OAuth2 Token Revocation specification.
package revocation

import (
	"net/http"

	"github.com/gonfire/oauth2"
)

// The known OAuth2 token types.
const (
	AccessToken  = "access_token"
	RefreshToken = "refresh_token"
)

// KnownTokenType returns true if the token type is a known token type
// (e.g. access token or refresh token).
func KnownTokenType(str string) bool {
	switch str {
	case AccessToken,
		RefreshToken:
		return true
	}

	return false
}

// A Request is typically returned by ParseRequest and holds all
// information necessary to handle a revocation request.
type Request struct {
	Token         string
	TokenTypeHint string
	ClientID      string
	ClientSecret  string
	HTTP          *http.Request
}

// ParseRequest parses an incoming request and returns a Request.
// The functions validates basic constraints given by the OAuth2 spec.
func ParseRequest(r *http.Request) (*Request, error) {
	// check method
	if r.Method != "POST" {
		return nil, oauth2.InvalidRequest(oauth2.NoState, "Invalid HTTP method")
	}

	// parse query params and body params to form
	err := r.ParseForm()
	if err != nil {
		return nil, oauth2.InvalidRequest(oauth2.NoState, "Malformed query parameters or body form")
	}

	// get token
	token := r.PostForm.Get("token")
	if token == "" {
		return nil, oauth2.InvalidRequest(oauth2.NoState, "Missing token")
	}

	// get token type hint
	tokenTypeHint := r.PostForm.Get("token_type_hint")

	// get client id and secret
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		return nil, oauth2.InvalidRequest(oauth2.NoState, "Missing or invalid HTTP authorization header")
	}

	return &Request{
		Token:         token,
		TokenTypeHint: tokenTypeHint,
		ClientID:      clientID,
		ClientSecret:  clientSecret,
		HTTP:          r,
	}, nil
}

// UnsupportedTokenType constructs an error that indicates that the authorization
// server does not support the revocation of the presented token type.
func UnsupportedTokenType(description string) *oauth2.Error {
	return &oauth2.Error{
		Status:      http.StatusBadRequest,
		Name:        "unsupported_token_type",
		Description: description,
	}
}
