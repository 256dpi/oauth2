package oauth2

import (
	"net/http"
	"strconv"
)

type TokenResponse struct {
	TokenType    string            `json:"token_type"`
	AccessToken  string            `json:"access_token"`
	ExpiresIn    int               `json:"expires_in"`
	RefreshToken string            `json:"refresh_token,omitempty"`
	Scope        Scope             `json:"scope,omitempty"`
	State        string            `json:"state,omitempty"`
	ExtraFields  map[string]string `json:",inline"`
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

	// add extra fields
	for k, v := range r.ExtraFields {
		m[k] = v
	}

	return m
}

func WriteTokenResponse(w http.ResponseWriter, res *TokenResponse) error {
	return WriteJSON(w, res, http.StatusOK)
}

func WriteTokenResponseRedirect(w http.ResponseWriter, uri string, res *TokenResponse) error {
	return WriteRedirect(w, uri, nil, res.Map())
}

type AuthorizationCodeResponse struct {
	Code  string `json:"code"`
	State string `json:"state,omitempty"`
}

func NewAuthorizationCodeResponse(code string) *AuthorizationCodeResponse {
	return &AuthorizationCodeResponse{
		Code: code,
	}
}

func (r *AuthorizationCodeResponse) Map() map[string]string {
	m := make(map[string]string)

	// add code
	m["code"] = r.Code

	// add state if present
	if len(r.State) > 0 {
		m["state"] = r.State
	}

	return m
}

func WriteAuthorizationCodeResponse(w http.ResponseWriter, res *AuthorizationCodeResponse) error {
	return WriteJSON(w, res, http.StatusOK)
}

func WriteAuthorizationCodeResponseRedirect(w http.ResponseWriter, uri string, res *AuthorizationCodeResponse) error {
	return WriteRedirect(w, uri, nil, res.Map())
}
