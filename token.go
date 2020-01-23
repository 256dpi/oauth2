package oauth2

import (
	"net/http"
	"net/url"
	"strconv"
)

// A TokenRequest is typically returned by ParseTokenRequest and holds all
// information necessary to handle a token request.
type TokenRequest struct {
	GrantType    string
	Scope        Scope
	ClientID     string
	ClientSecret string
	Username     string
	Password     string
	RefreshToken string
	RedirectURI  string
	Code         string
}

// ParseTokenRequest parses an incoming request and returns a TokenRequest.
// The functions validates basic constraints given by the OAuth2 spec.
//
// Note: Obtaining the client id and secret from the request body (form data)
// is not implemented by default due to security considerations.
func ParseTokenRequest(r *http.Request) (*TokenRequest, error) {
	// check method
	if r.Method != "POST" {
		return nil, InvalidRequest("invalid HTTP method")
	}

	// parse query params and body params to form
	err := r.ParseForm()
	if err != nil {
		return nil, InvalidRequest("malformed query parameters or body form")
	}

	// get grant type
	grantType := r.PostForm.Get("grant_type")
	if grantType == "" {
		return nil, InvalidRequest("missing grant type")
	}

	// get scope
	scope := ParseScope(r.PostForm.Get("scope"))

	// get client id and secret
	clientID, clientSecret, ok := r.BasicAuth()
	if !ok {
		return nil, InvalidRequest("missing or invalid HTTP authorization header")
	}

	// get username and password
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")

	// get refresh token
	refreshToken := r.PostForm.Get("refresh_token")

	// get redirect uri
	redirectURIString, err := url.QueryUnescape(r.PostForm.Get("redirect_uri"))
	if err != nil {
		return nil, InvalidRequest("invalid redirect URI")
	}

	// validate redirect uri if present
	if redirectURIString != "" {
		redirectURI, err := url.ParseRequestURI(redirectURIString)
		if err != nil || redirectURI.Fragment != "" {
			return nil, InvalidRequest("invalid redirect URI")
		}
	}

	// get code
	code := r.PostForm.Get("code")

	return &TokenRequest{
		GrantType:    grantType,
		Scope:        scope,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		Username:     username,
		Password:     password,
		RefreshToken: refreshToken,
		RedirectURI:  redirectURIString,
		Code:         code,
	}, nil
}

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
// and state.
func (r *TokenResponse) SetRedirect(uri, state string) *TokenResponse {
	r.RedirectURI = uri
	r.State = state

	return r
}

// Map returns a map of all fields that can be presented to the client. This
// method can be used to construct query parameters or a fragment when
// redirecting the token response.
func (r *TokenResponse) Map() map[string]string {
	m := make(map[string]string)

	// add token type
	m["token_type"] = r.TokenType

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
// If the RedirectURI field is present on the response a redirection that
// transmits the token in the fragment will be written instead.
func WriteTokenResponse(w http.ResponseWriter, r *TokenResponse) error {
	// write redirect if requested
	if r.RedirectURI != "" {
		return WriteRedirect(w, r.RedirectURI, r.Map(), true)
	}

	return Write(w, r, http.StatusOK)
}
