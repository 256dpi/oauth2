package oauth2

import (
	"net/http"
	"net/url"
)

type GrantType string

func (t GrantType) Password() bool {
	return t == "password"
}

func (t GrantType) ClientCredentials() bool {
	return t == "client_credentials"
}

func (t GrantType) AuthorizationCode() bool {
	return t == "authorization_code"
}

func (t GrantType) RefreshToken() bool {
	return t == "refresh_token"
}

func (t GrantType) Known() bool {
	return t.Password() || t.ClientCredentials() ||
		t.AuthorizationCode() || t.RefreshToken()
}

func (t GrantType) Extension() bool {
	_, err := url.ParseRequestURI(string(t))
	return err == nil
}

type AccessRequest struct {
	GrantType    GrantType
	Scope        string
	ClientID     string
	ClientSecret string
	Username     string
	Password     string
	RefreshToken string
}

func (r *AccessRequest) Confidential() bool {
	return len(r.ClientID) > 0 && len(r.ClientSecret) > 0
}

func ParseAccessRequest(req *http.Request) (*AccessRequest, error) {
	// check method
	if req.Method != "POST" {
		return nil, ErrorWithCode(InvalidRequest, "Invalid HTTP method")
	}

	// parse query params and body params to form
	err := req.ParseForm()
	if err != nil {
		return nil, ErrorWithCode(InvalidRequest, "Malformed query parameters or body form")
	}

	// get grant type and scope
	grantType := req.PostForm.Get("grant_type")
	scope := req.PostForm.Get("scope")

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

	return &AccessRequest{
		GrantType:    GrantType(grantType),
		Scope:        scope,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Username:     username,
		Password:     password,
		RefreshToken: refreshToken,
	}, nil
}

type ResponseType string

func (t ResponseType) Token() bool {
	return t == "token"
}

func (t ResponseType) Code() bool {
	return t == "code"
}

func (t ResponseType) Known() bool {
	return t.Token() || t.Code()
}

type AuthorizationRequest struct {
	ResponseType ResponseType
	Scope        []string
	ClientID     string
	RedirectURI  string
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

	return nil, nil
}
