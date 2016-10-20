package oauth2

import (
	"net/http"
	"net/url"
)

// A TokenRequest is typically returned by ParseTokenRequest and holds all
// information necessary to handle a token request.
type TokenRequest struct {
	GrantType    string
	Scope        Scope
	ClientID     string
	ClientSecret string
	Username     string
	Password     string
	RefreshToken string
	RedirectURI  string
	State        string
	Code         string

	HTTP *http.Request
}

// ParseTokenRequest parses an incoming request and returns a TokenRequest.
// The functions validates basic constraints given by the OAuth2 spec.
//
// Note: Obtaining the client id and secret from the request body (form data)
// is not implemented by default due to security considerations.
func ParseTokenRequest(r *http.Request) (*TokenRequest, error) {
	// check method
	if r.Method != "POST" {
		return nil, InvalidRequest(NoState, "Invalid HTTP method")
	}

	// parse query params and body params to form
	err := r.ParseForm()
	if err != nil {
		return nil, InvalidRequest(NoState, "Malformed query parameters or body form")
	}

	// get state
	state := r.PostForm.Get("state")

	// get grant type
	grantType := r.PostForm.Get("grant_type")
	if grantType == "" {
		return nil, InvalidRequest(state, "Missing grant type")
	}

	// get scope
	scope := ParseScope(r.PostForm.Get("scope"))

	// get client id and secret
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		return nil, InvalidRequest(state, "Missing or invalid HTTP authorization header")
	}

	// get username and password
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")

	// get refresh token
	refreshToken := r.PostForm.Get("refresh_token")

	// get redirect uri
	redirectURIString, err := url.QueryUnescape(r.Form.Get("redirect_uri"))
	if err != nil {
		return nil, InvalidRequest(state, "Invalid redirect URI")
	}

	// validate redirect uri if present
	if redirectURIString != "" {
		redirectURI, err := url.ParseRequestURI(redirectURIString)
		if err != nil || redirectURI.Fragment != "" {
			return nil, InvalidRequest(state, "Invalid redirect URI")
		}
	}

	// get code
	code := r.PostForm.Get("code")

	return &TokenRequest{
		GrantType:    grantType,
		Scope:        scope,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Username:     username,
		Password:     password,
		RefreshToken: refreshToken,
		RedirectURI:  redirectURIString,
		State:        state,
		Code:         code,
		HTTP:         r,
	}, nil
}

// A AuthorizationRequest is typically returned by ParseAuthorizationRequest and
// holds all information necessary to handle an authorization request.
type AuthorizationRequest struct {
	ResponseType string
	Scope        Scope
	ClientID     string
	RedirectURI  string
	State        string

	HTTP *http.Request
}

// ParseAuthorizationRequest parses an incoming request and returns an
// AuthorizationRequest. The functions validates basic constraints given by the
// OAuth2 spec.
func ParseAuthorizationRequest(r *http.Request) (*AuthorizationRequest, error) {
	// check method
	if r.Method != "GET" && r.Method != "POST" {
		return nil, InvalidRequest(NoState, "Invalid HTTP method")
	}

	// parse query params and body params to form
	err := r.ParseForm()
	if err != nil {
		return nil, InvalidRequest(NoState, "Malformed query parameters or form data")
	}

	// get state
	state := r.Form.Get("state")

	// get response type
	responseType := r.Form.Get("response_type")
	if responseType == "" {
		return nil, InvalidRequest(state, "Missing response type")
	}

	// get scope
	scope := ParseScope(r.Form.Get("scope"))

	// get client id
	clientID := r.Form.Get("client_id")
	if clientID == "" {
		return nil, InvalidRequest(state, "Missing client ID")
	}

	// get redirect uri
	redirectURIString, err := url.QueryUnescape(r.Form.Get("redirect_uri"))
	if err != nil || redirectURIString == "" {
		return nil, InvalidRequest(state, "Missing redirect URI")
	}

	// parse redirect uri
	redirectURI, err := url.ParseRequestURI(redirectURIString)
	if err != nil || redirectURI.Fragment != "" {
		return nil, InvalidRequest(state, "Invalid redirect URI")
	}

	return &AuthorizationRequest{
		ResponseType: responseType,
		Scope:        scope,
		ClientID:     clientID,
		RedirectURI:  redirectURIString,
		State:        state,
		HTTP:         r,
	}, nil
}
