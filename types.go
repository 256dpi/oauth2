package oauth2

import (
	"encoding/json"
	"net/url"
	"strings"
)

type GrantType string

func (t GrantType) Password() bool {
	return t == "password"
}

func (t GrantType) ClientCredentials() bool {
	return t == "client_credentials"
}

func (t GrantType) AuthorizationCode() bool {
	return t == "authorization_code"
}

func (t GrantType) RefreshToken() bool {
	return t == "refresh_token"
}

func (t GrantType) Known() bool {
	return t.Password() || t.ClientCredentials() ||
		t.AuthorizationCode() || t.RefreshToken()
}

func (t GrantType) Extension() bool {
	_, err := url.ParseRequestURI(string(t))
	return err == nil
}

type Scope []string

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

func (s Scope) Contains(str string) bool {
	for _, i := range s {
		if i == str {
			return true
		}
	}

	return false
}

func (s Scope) Includes(scope Scope) bool {
	for _, i := range scope {
		if !s.Contains(i) {
			return false
		}
	}

	return true
}

func (s Scope) String() string {
	return strings.Join(s, " ")
}

func (s Scope) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}

type ResponseType string

func (t ResponseType) Token() bool {
	return t == "token"
}

func (t ResponseType) Code() bool {
	return t == "code"
}

func (t ResponseType) Known() bool {
	return t.Token() || t.Code()
}
