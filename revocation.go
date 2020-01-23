package oauth2

import (
	"net/http"
	"net/url"
	"strings"
)

// A RevocationRequest is returned by ParseRevocationRequest and holds all
// information necessary to handle a revocation request.
type RevocationRequest struct {
	Token         string
	TokenTypeHint string
	ClientID      string
	ClientSecret  string
}

// ParseRevocationRequest parses an incoming request and returns a
// RevocationRequest. The functions validates basic constraints given by the
// OAuth2 spec.
func ParseRevocationRequest(r *http.Request) (*RevocationRequest, error) {
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

	return &RevocationRequest{
		Token:         token,
		TokenTypeHint: tokenTypeHint,
		ClientID:      clientID,
		ClientSecret:  clientSecret,
	}, nil
}

// RevocationRequestValues will return the form values for the provided request.
func RevocationRequestValues(r RevocationRequest) url.Values {
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

// BuildRevocationRequest will build the provided request.
func BuildRevocationRequest(uri string, r RevocationRequest) (*http.Request, error) {
	// prepare body
	body := strings.NewReader(RevocationRequestValues(r).Encode())

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
