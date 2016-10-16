package oauth2

import (
	"net/http"
	"strconv"
)

type TokenResponse struct {
	TokenType    string `json:"token_type"`
	AccessToken  string `json:"access_token"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        Scope  `json:"scope,omitempty"`
	State        string `json:"state,omitempty"`
}

func NewTokenResponse(tokenType, accessToken string, expiresIn int) *TokenResponse {
	return &TokenResponse{
		TokenType:   tokenType,
		AccessToken: accessToken,
		ExpiresIn:   expiresIn,
	}
}

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

func WriteTokenResponse(w http.ResponseWriter, res *TokenResponse) error {
	return Write(w, res, http.StatusOK)
}

func RedirectTokenResponse(w http.ResponseWriter, uri string, res *TokenResponse) error {
	return Redirect(w, uri, res.Map(), true)
}

type CodeResponse struct {
	Code  string `json:"code"`
	State string `json:"state,omitempty"`
}

func NewCodeResponse(code string) *CodeResponse {
	return &CodeResponse{
		Code: code,
	}
}

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

func RedirectCodeResponse(w http.ResponseWriter, uri string, res *CodeResponse) error {
	return Redirect(w, uri, res.Map(), false)
}
