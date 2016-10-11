package oauth2

import "net/http"

type AccessRequest struct {
	GrantType    GrantType
	Scope        Scope
	ClientID     string
	ClientSecret string
	Username     string
	Password     string
	RefreshToken string
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

func (r *AccessRequest) Confidential() bool {
	return len(r.ClientID) > 0 && len(r.ClientSecret) > 0
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
