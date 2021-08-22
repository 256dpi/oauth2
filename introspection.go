package oauth2

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"strings"
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
// IntrospectionRequest. The function validates basic constraints given by the
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

// IntrospectionRequestValues will return the form values for the provided request.
func IntrospectionRequestValues(r IntrospectionRequest) url.Values {
	// prepare slice
	slice := []string{
		r.Token,
		r.TokenTypeHint,
	}

	// prepare values
	values := make(url.Values, len(slice))

	// set token if available
	if r.Token != "" {
		values["token"] = slice[0:1]
	}

	// set token type hint if available
	if len(r.TokenTypeHint) != 0 {
		values["token_type_hint"] = slice[1:2]
	}

	return values
}

// BuildIntrospectionRequest will build the provided request.
func BuildIntrospectionRequest(uri string, r IntrospectionRequest) (*http.Request, error) {
	// prepare body
	body := strings.NewReader(IntrospectionRequestValues(r).Encode())

	// create request
	req, err := http.NewRequest("POST", uri, body)
	if err != nil {
		return nil, err
	}

	// set basic auth if available
	if r.ClientID != "" || r.ClientSecret != "" {
		req.SetBasicAuth(r.ClientID, r.ClientSecret)
	}

	// set content type
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	return req, nil
}

// ParseIntrospectionResponse will parse the provided response.
func ParseIntrospectionResponse(res *http.Response, limit int64) (*IntrospectionResponse, error) {
	// read response
	data, err := ioutil.ReadAll(io.LimitReader(res.Body, limit))
	if err != nil {
		return nil, err
	}

	// parse content type
	contentType, _, err := mime.ParseMediaType(res.Header.Get("Content-Type"))
	if err != nil {
		return nil, err
	}

	// check content type
	if contentType != "application/json" {
		return nil, fmt.Errorf("unexpected content type: %q", contentType)
	}

	// decode introspection response
	var irs IntrospectionResponse
	err = json.Unmarshal(data, &irs)
	if err != nil {
		return nil, err
	}

	return &irs, nil
}
