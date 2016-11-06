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

	RedirectURI string `json:"-"`
	UseFragment bool   `json:"-"`
}

// NewTokenResponse constructs a TokenResponse.
func NewTokenResponse(tokenType, accessToken string, expiresIn int) *TokenResponse {
	return &TokenResponse{
		TokenType:   tokenType,
		AccessToken: accessToken,
		ExpiresIn:   expiresIn,
	}
}

// SetRedirect marks the response to be redirected by setting the redirect URI
// and whether the response should be added to the query parameter or fragment
// part of the URI.
func (r *TokenResponse) SetRedirect(uri, state string, useFragment bool) *TokenResponse {
	r.RedirectURI = uri
	r.State = state
	r.UseFragment = useFragment

	return r
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
	if r.RefreshToken != "" {
		m["refresh_token"] = r.RefreshToken
	}

	// add scope if present
	if r.Scope != nil {
		m["scope"] = r.Scope.String()
	}

	// add state if present
	if r.State != "" {
		m["state"] = r.State
	}

	return m
}

// WriteTokenResponse will write the specified response to the response writer.
// If the RedirectURI field is present on the response a redirection will be
// written instead.
func WriteTokenResponse(w http.ResponseWriter, r *TokenResponse) error {
	// write redirect if requested
	if r.RedirectURI != "" {
		return WriteRedirect(w, r.RedirectURI, r.Map(), r.UseFragment)
	}

	return Write(w, r, http.StatusOK)
}

// A CodeResponse is typically constructed after an authorization code request
// has been authenticated to return an authorization code.
type CodeResponse struct {
	Code  string `json:"code"`
	State string `json:"state,omitempty"`

	RedirectURI string `json:"-"`
	UseFragment bool   `json:"-"`
}

// NewCodeResponse constructs a CodeResponse.
func NewCodeResponse(code, redirectURI, state string) *CodeResponse {
	return &CodeResponse{
		Code:        code,
		State:       state,
		RedirectURI: redirectURI,
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
	if r.State != "" {
		m["state"] = r.State
	}

	return m
}

// WriteCodeResponse will write a redirection based on the specified code
// response to the response writer.
func WriteCodeResponse(w http.ResponseWriter, r *CodeResponse) error {
	return WriteRedirect(w, r.RedirectURI, r.Map(), r.UseFragment)
}
