package oauth2

import (
	"net/http"
	"strconv"
)

type Response struct {
	TokenType    TokenType         `json:"token_type"`
	AccessToken  string            `json:"access_token"`
	ExpiresIn    int               `json:"expires_in"`
	RefreshToken string            `json:"refresh_token,omitempty"`
	Scope        Scope             `json:"scope,omitempty"`
	ExtraFields  map[string]string `json:",inline"`
}

func NewResponse(tokenType, accessToken string, expiresIn int) *Response {
	return &Response{
		TokenType:   tokenType,
		AccessToken: accessToken,
		ExpiresIn:   expiresIn,
	}
}

func (r *Response) Map() map[string]string {
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

	// add scope
	if r.Scope != nil {
		m["scope"] = r.Scope.String()
	}

	// add extra fields
	for k, v := range r.ExtraFields {
		m[k] = v
	}

	return m
}

func WriteResponse(w http.ResponseWriter, res *Response) error {
	return WriteJSON(w, res, http.StatusOK)
}

func WriteResponseRedirect(w http.ResponseWriter, res *Response, uri string) error {
	return WriteRedirect(w, uri, res.Map())
}
