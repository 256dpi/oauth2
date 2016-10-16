package oauth2

import (
	"net/http"
	"net/url"
)

type AccessTokenRequest struct {
	GrantType    GrantType
	Scope        Scope
	ClientID     string
	ClientSecret string
	Username     string
	Password     string
	RefreshToken string
	RedirectURI  string
	Code         string
}

func ParseAccessTokenRequest(req *http.Request) (*AccessTokenRequest, error) {
	// check method
	if req.Method != "POST" {
		return nil, ErrorWithCode(InvalidRequest, "Invalid HTTP method")
	}

	// parse query params and body params to form
	err := req.ParseForm()
	if err != nil {
		return nil, ErrorWithCode(InvalidRequest, "Malformed query parameters or body form")
	}

	// get grant type
	grantType := req.PostForm.Get("grant_type")
	if grantType == "" {
		return nil, ErrorWithCode(InvalidRequest, "Missing grant type")
	}

	// get scope
	scope := ParseScope(req.PostForm.Get("scope"))

	// TODO: Support client id and client secret in body form?

	// get client id and secret
	clientID, clientSecret, ok := req.BasicAuth()
	if !ok {
		return nil, ErrorWithCode(InvalidRequest, "Missing or invalid HTTP authorization header")
	}

	// get username and password
	username := req.PostForm.Get("username")
	password := req.PostForm.Get("password")

	// get refresh token
	refreshToken := req.PostForm.Get("refresh_token")

	// get redirect uri
	redirectURIString, err := url.QueryUnescape(req.Form.Get("redirect_uri"))
	if err != nil {
		return nil, ErrorWithCode(InvalidRequest, "Missing redirect URI")
	}

	// validate redirect uri if present
	if len(redirectURIString) > 0 {
		redirectURI, err := url.ParseRequestURI(redirectURIString)
		if err != nil || redirectURI.Fragment != "" {
			return nil, ErrorWithCode(InvalidRequest, "Invalid redirect URI")
		}
	}

	// get code
	code := req.PostForm.Get("code")

	return &AccessTokenRequest{
		GrantType:    GrantType(grantType),
		Scope:        scope,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Username:     username,
		Password:     password,
		RefreshToken: refreshToken,
		RedirectURI:  redirectURIString,
		Code:         code,
	}, nil
}

func (r *AccessTokenRequest) Confidential() bool {
	return len(r.ClientID) > 0 && len(r.ClientSecret) > 0
}

type AuthorizationRequest struct {
	ResponseType ResponseType
	Scope        []string
	ClientID     string
	RedirectURI  string
	State        string
}

func ParseAuthorizationRequest(req *http.Request) (*AuthorizationRequest, error) {
	// check method
	if req.Method != "GET" && req.Method != "POST" {
		return nil, ErrorWithCode(InvalidRequest, "Invalid HTTP method")
	}

	// parse query params and body params to form
	err := req.ParseForm()
	if err != nil {
		return nil, ErrorWithCode(InvalidRequest, "Malformed query parameters or body form")
	}

	// get response type
	responseType := req.Form.Get("response_type")
	if responseType == "" {
		return nil, ErrorWithCode(InvalidRequest, "Missing response type")
	}

	// get scope
	scope := ParseScope(req.Form.Get("scope"))

	// get client id
	clientID := req.Form.Get("client_id")
	if clientID == "" {
		return nil, ErrorWithCode(InvalidRequest, "Missing client ID")
	}

	// get redirect uri
	redirectURIString, err := url.QueryUnescape(req.Form.Get("redirect_uri"))
	if err != nil {
		return nil, ErrorWithCode(InvalidRequest, "Missing redirect URI")
	}

	// parse redirect uri
	redirectURI, err := url.ParseRequestURI(redirectURIString)
	if err != nil || redirectURI.Fragment != "" {
		return nil, ErrorWithCode(InvalidRequest, "Invalid redirect URI")
	}

	// get state
	state := req.Form.Get("state")

	return &AuthorizationRequest{
		ResponseType: ResponseType(responseType),
		Scope:        scope,
		ClientID:     clientID,
		RedirectURI:  redirectURIString,
		State:        state,
	}, nil
}
