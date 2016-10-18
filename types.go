package oauth2

import (
	"encoding/json"
	"net/url"
	"strings"
)

// A GrantType is typically received in a token request.
type GrantType string

// Strings implements the fmt.Stringer interface.
func (t GrantType) String() string {
	return string(t)
}

// Password returns true if the grant type is a password grant type.
func (t GrantType) Password() bool {
	return t == "password"
}

// ClientCredentials returns true if the grant type is a client credentials
// grant type.
func (t GrantType) ClientCredentials() bool {
	return t == "client_credentials"
}

// AuthorizationCode returns true if the grant type is a authorization code
// grant type.
func (t GrantType) AuthorizationCode() bool {
	return t == "authorization_code"
}

// RefreshToken returns true if the grant type is a refresh token grant type.
func (t GrantType) RefreshToken() bool {
	return t == "refresh_token"
}

// Known returns true if the grant type is a known grant type (e.g. password,
// client credentials, authorization code or refresh token).
func (t GrantType) Known() bool {
	return t.Password() || t.ClientCredentials() ||
		t.AuthorizationCode() || t.RefreshToken()
}

// Extension returns true if the grant type is valid extension grant type.
func (t GrantType) Extension() bool {
	_, err := url.ParseRequestURI(string(t))
	return err == nil
}

// A Scope is received typically in an authorization and token request.
type Scope []string

// ParseScope parses the joined string representation of a scope.
func ParseScope(str string) Scope {
	// split string
	list := strings.Split(str, " ")

	// prepare result
	var res []string

	// process items
	for _, item := range list {
		// trim whitespace
		item = strings.TrimSpace(item)

		if item != "" {
			res = append(res, item)
		}
	}

	return Scope(res)
}

// Contains returns true if the specified string is part of the scope.
func (s Scope) Contains(str string) bool {
	for _, i := range s {
		if i == str {
			return true
		}
	}

	return false
}

// Includes returns true if the specified scope is included in this scope.
func (s Scope) Includes(scope Scope) bool {
	for _, i := range scope {
		if !s.Contains(i) {
			return false
		}
	}

	return true
}

// String implements the fmt.Stringer interface.
func (s Scope) String() string {
	return strings.Join(s, " ")
}

// MarshalJSON implements the json.Marshaler interface.
func (s Scope) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

// A ResponseType is typically received in an authorization request.
type ResponseType string

// String implements the fmt.Stringer interface.
func (t ResponseType) String() string {
	return string(t)
}

// Token returns true if the response type is a token response type.
func (t ResponseType) Token() bool {
	return t == "token"
}

// Code returns true if the response type is a code response type.
func (t ResponseType) Code() bool {
	return t == "code"
}

// Known returns true if the response type is a known response type (e.g. token,
// or code).
func (t ResponseType) Known() bool {
	return t.Token() || t.Code()
}
