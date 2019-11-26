package introspection

import (
	"fmt"
	"net/http"

	"github.com/256dpi/oauth2"
)

// Response is a response returned by the token introspection endpoint.
type Response struct {
	Active     bool   `json:"active"`
	Scope      string `json:"scope,omitempty"`
	ClientID   string `json:"client_id,omitempty"`
	Username   string `json:"username,omitempty"`
	TokenType  string `json:"token_type,omitempty"`
	ExpiresAt  int64  `json:"exp,omitempty"`
	IssuedAt   int64  `json:"iat,omitempty"`
	NotBefore  int64  `json:"nbf,omitempty"`
	Subject    string `json:"sub,omitempty"`
	Audience   string `json:"aud,omitempty"`
	Issuer     string `json:"iss,omitempty"`
	Identifier string `json:"jti,omitempty"`

	Extra map[string]interface{} `json:"extra,omitempty"`
}

// NewResponse constructs a Response.
func NewResponse(active bool, scope, clientID, username, tokenType string) *Response {
	return &Response{
		Active:    active,
		Scope:     scope,
		ClientID:  clientID,
		Username:  username,
		TokenType: tokenType,
	}
}

// WriteResponse will write a response to the response writer.
func WriteResponse(w http.ResponseWriter, r *Response) error {
	// check token type
	if r.Active && !KnownTokenType(r.TokenType) {
		return fmt.Errorf("unknown token type")
	}

	return oauth2.Write(w, r, http.StatusOK)
}
