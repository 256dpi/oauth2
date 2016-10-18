// Package oauth2 provides structures and functions to implement OAuth2
// compatible authentication servers. The library can be used with any framework
// and is built on top of the standard Go http library.
package oauth2

import (
	"net/http"
	"net/url"
)

// The available known OAuth2 grant types.
const (
	PasswordGrantType          = "password"
	ClientCredentialsGrantType = "client_credentials"
	AuthorizationCodeGrantType = "authorization_code"
	RefreshTokenGrantType      = "refresh_token"
)

// KnownGrantType returns true if the grant type is a known grant type
// (e.g. password, client credentials, authorization code or refresh token).
func KnownGrantType(str string) bool {
	switch str {
	case PasswordGrantType,
		ClientCredentialsGrantType,
		AuthorizationCodeGrantType,
		RefreshTokenGrantType:
		return true
	}

	return false
}

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
}

// Note: Obtaining the client id and secret from the request body (form data)
// is not implemented by default due to security considerations.
func ParseTokenRequest(req *http.Request) (*TokenRequest, error) {
	// check method
	if req.Method != "POST" {
		return nil, InvalidRequest(NoState, "Invalid HTTP method")
	}

	// parse query params and body params to form
	err := req.ParseForm()
	if err != nil {
		return nil, InvalidRequest(NoState, "Malformed query parameters or body form")
	}

	// get state
	state := req.PostForm.Get("state")

	// get grant type
	grantType := req.PostForm.Get("grant_type")
	if grantType == "" {
		return nil, InvalidRequest(state, "Missing grant type")
	}

	// get scope
	scope := ParseScope(req.PostForm.Get("scope"))

	// get client id and secret
	clientID, clientSecret, ok := req.BasicAuth()
	if !ok {
		return nil, InvalidRequest(state, "Missing or invalid HTTP authorization header")
	}

	// get username and password
	username := req.PostForm.Get("username")
	password := req.PostForm.Get("password")

	// get refresh token
	refreshToken := req.PostForm.Get("refresh_token")

	// get redirect uri
	redirectURIString, err := url.QueryUnescape(req.Form.Get("redirect_uri"))
	if err != nil {
		return nil, InvalidRequest(state, "Invalid redirect URI")
	}

	// validate redirect uri if present
	if len(redirectURIString) > 0 {
		redirectURI, err := url.ParseRequestURI(redirectURIString)
		if err != nil || redirectURI.Fragment != "" {
			return nil, InvalidRequest(state, "Invalid redirect URI")
		}
	}

	// get code
	code := req.PostForm.Get("code")

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
	}, nil
}

func (r *TokenRequest) Confidential() bool {
	return len(r.ClientID) > 0 && len(r.ClientSecret) > 0
}

// The available known OAuth2 response types.
const (
	TokenResponseType = "token"
	CodeResponseType  = "code"
)

// Known returns true if the response type is a known response type (e.g. token,
// or code).
func KnownResponseType(str string) bool {
	switch str {
	case TokenResponseType, CodeResponseType:
		return true
	}

	return false
}

type AuthorizationRequest struct {
	ResponseType string
	Scope        Scope
	ClientID     string
	RedirectURI  string
	State        string
}

func ParseAuthorizationRequest(req *http.Request) (*AuthorizationRequest, error) {
	// check method
	if req.Method != "GET" && req.Method != "POST" {
		return nil, InvalidRequest(NoState, "Invalid HTTP method")
	}

	// parse query params and body params to form
	err := req.ParseForm()
	if err != nil {
		return nil, InvalidRequest(NoState, "Malformed query parameters or form data")
	}

	// get state
	state := req.Form.Get("state")

	// get response type
	responseType := req.Form.Get("response_type")
	if responseType == "" {
		return nil, InvalidRequest(state, "Missing response type")
	}

	// get scope
	scope := ParseScope(req.Form.Get("scope"))

	// get client id
	clientID := req.Form.Get("client_id")
	if clientID == "" {
		return nil, InvalidRequest(state, "Missing client ID")
	}

	// get redirect uri
	redirectURIString, err := url.QueryUnescape(req.Form.Get("redirect_uri"))
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
	}, nil
}
