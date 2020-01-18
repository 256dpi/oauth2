package oauth2

import (
	"fmt"
	"net/http"
)

// A IntrospectionRequest is returned by ParseIntrospectionRequest and holds all
// information necessary to handle an introspection request.
type IntrospectionRequest struct {
	Token         string
	TokenTypeHint string
	ClientID      string
	ClientSecret  string
}

// ParseIntrospectionRequest parses an incoming request and returns an
// IntrospectionRequest. The functions validates basic constraints given by the
// OAuth2 spec.
func ParseIntrospectionRequest(r *http.Request) (*IntrospectionRequest, error) {
	// check method
	if r.Method != "POST" {
		return nil, InvalidRequest("invalid HTTP method")
	}

	// parse query params and body params to form
	err := r.ParseForm()
	if err != nil {
		return nil, InvalidRequest("malformed query parameters or body form")
	}

	// get token
	token := r.PostForm.Get("token")
	if token == "" {
		return nil, InvalidRequest("missing token")
	}

	// get token type hint
	tokenTypeHint := r.PostForm.Get("token_type_hint")

	// get client id and secret
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		return nil, InvalidRequest("missing or invalid HTTP authorization header")
	}

	return &IntrospectionRequest{
		Token:         token,
		TokenTypeHint: tokenTypeHint,
		ClientID:      clientID,
		ClientSecret:  clientSecret,
	}, nil
}

// IntrospectionResponse is a response returned by the token introspection
// endpoint.
type IntrospectionResponse struct {
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

// NewIntrospectionResponse constructs an IntrospectionResponse.
func NewIntrospectionResponse(active bool, scope, clientID, username, tokenType string) *IntrospectionResponse {
	return &IntrospectionResponse{
		Active:    active,
		Scope:     scope,
		ClientID:  clientID,
		Username:  username,
		TokenType: tokenType,
	}
}

// WriteIntrospectionResponse will write a response to the response writer.
func WriteIntrospectionResponse(w http.ResponseWriter, r *IntrospectionResponse) error {
	// check token type
	if r.Active && !KnownTokenType(r.TokenType) {
		return fmt.Errorf("unknown token type")
	}

	return Write(w, r, http.StatusOK)
}
