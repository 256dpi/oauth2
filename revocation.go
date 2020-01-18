package oauth2

import (
	"net/http"
)

// A RevocationRequest is returned by ParseRevocationRequest and holds all
// information necessary to handle a revocation request.
type RevocationRequest struct {
	Token         string
	TokenTypeHint string
	ClientID      string
	ClientSecret  string
}

// ParseRevocationRequest parses an incoming request and returns a
// RevocationRequest. The functions validates basic constraints given by the
// OAuth2 spec.
func ParseRevocationRequest(r *http.Request) (*RevocationRequest, error) {
	// check method
	if r.Method != "POST" {
		return nil, InvalidRequest("invalid HTTP method")
	}

	// parse query params and body params to form
	err := r.ParseForm()
	if err != nil {
		return nil, InvalidRequest("malformed query parameters or body form")
	}

	// get token
	token := r.PostForm.Get("token")
	if token == "" {
		return nil, InvalidRequest("missing token")
	}

	// get token type hint
	tokenTypeHint := r.PostForm.Get("token_type_hint")

	// get client id and secret
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		return nil, InvalidRequest("missing or invalid HTTP authorization header")
	}

	return &RevocationRequest{
		Token:         token,
		TokenTypeHint: tokenTypeHint,
		ClientID:      clientID,
		ClientSecret:  clientSecret,
	}, nil
}
