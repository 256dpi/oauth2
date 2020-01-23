package oauth2

import (
	"net/http"
	"net/url"
)

// A AuthorizationRequest is typically returned by ParseAuthorizationRequest and
// holds all information necessary to handle an authorization request.
type AuthorizationRequest struct {
	ResponseType string
	Scope        Scope
	ClientID     string
	RedirectURI  string
	State        string
}

// ParseAuthorizationRequest parses an incoming request and returns an
// AuthorizationRequest. The functions validates basic constraints given by the
// OAuth2 spec.
func ParseAuthorizationRequest(r *http.Request) (*AuthorizationRequest, error) {
	// check method
	if r.Method != "GET" && r.Method != "POST" {
		return nil, InvalidRequest("invalid HTTP method")
	}

	// parse query params and body params to form
	err := r.ParseForm()
	if err != nil {
		return nil, InvalidRequest("malformed query parameters or form data")
	}

	// get state
	state := r.Form.Get("state")

	// get response type
	responseType := r.Form.Get("response_type")
	if responseType == "" {
		return nil, InvalidRequest("missing response type")
	}

	// get scope
	scope := ParseScope(r.Form.Get("scope"))

	// get client id
	clientID := r.Form.Get("client_id")
	if clientID == "" {
		return nil, InvalidRequest("missing client ID")
	}

	// get redirect uri
	redirectURIString, err := url.QueryUnescape(r.Form.Get("redirect_uri"))
	if err != nil || redirectURIString == "" {
		return nil, InvalidRequest("missing redirect URI")
	}

	// parse redirect uri
	redirectURI, err := url.ParseRequestURI(redirectURIString)
	if err != nil || redirectURI.Fragment != "" {
		return nil, InvalidRequest("invalid redirect URI")
	}

	return &AuthorizationRequest{
		ResponseType: responseType,
		Scope:        scope,
		ClientID:     clientID,
		RedirectURI:  redirectURIString,
		State:        state,
	}, nil
}
