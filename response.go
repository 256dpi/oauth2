package oauth2

import (
	"net/http"
	"strconv"
)

// A TokenResponse is typically constructed after a token request has been
// authenticated and authorized to return an access token, a potential refresh
// token and more detailed information.
type TokenResponse struct {
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        Scope  `json:"scope,omitempty"`
	State        string `json:"state,omitempty"`
}

// NewTokenResponse constructs a TokenResponse.
func NewTokenResponse(tokenType, accessToken string, expiresIn int) *TokenResponse {
	return &TokenResponse{
		TokenType:   tokenType,
		AccessToken: accessToken,
		ExpiresIn:   expiresIn,
	}
}

// Map returns a map of all fields that can be presented to the client. This
// method can be used to construct query parameters or a fragment when
// redirecting the token response.
func (r *TokenResponse) Map() map[string]string {
	m := make(map[string]string)

	// add token type
	m["token_type"] = string(r.TokenType)

	// add access token
	m["access_token"] = r.AccessToken

	// add expires in
	m["expires_in"] = strconv.Itoa(r.ExpiresIn)

	// add description
	if len(r.RefreshToken) > 0 {
		m["refresh_token"] = r.RefreshToken
	}

	// add scope if present
	if r.Scope != nil {
		m["scope"] = r.Scope.String()
	}

	// add state if present
	if len(r.State) > 0 {
		m["state"] = r.State
	}

	return m
}

// WriteTokenResponse will write the specified response to the response writer.
func WriteTokenResponse(w http.ResponseWriter, res *TokenResponse) error {
	return Write(w, res, http.StatusOK)
}

// RedirectTokenResponse will write a redirection based on the specified token
// response to the response writer.
func RedirectTokenResponse(w http.ResponseWriter, uri string, res *TokenResponse) error {
	return Redirect(w, uri, res.Map(), true)
}

// A CodeResponse is typically constructed after an authorization code request
// has been authenticated to return an authorization code.
type CodeResponse struct {
	Code  string `json:"code"`
	State string `json:"state,omitempty"`
}

// NewCodeResponse constructs a CodeResponse.
func NewCodeResponse(code string) *CodeResponse {
	return &CodeResponse{
		Code: code,
	}
}

// Map returns a map of all fields that can be presented to the client. This
// method can be used to construct query parameters or a fragment when
// redirecting the code response.
func (r *CodeResponse) Map() map[string]string {
	m := make(map[string]string)

	// add code
	m["code"] = r.Code

	// add state if present
	if len(r.State) > 0 {
		m["state"] = r.State
	}

	return m
}

// RedirectCodeResponse will write a redirection based on the specified code
// response to the response writer.
func RedirectCodeResponse(w http.ResponseWriter, uri string, res *CodeResponse) error {
	return Redirect(w, uri, res.Map(), false)
}
