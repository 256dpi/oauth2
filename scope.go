package oauth2

import (
	"encoding/json"
	"strings"
)

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

	return res
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

// Empty return true if the scope is empty.
func (s Scope) Empty() bool {
	return len(s) == 0
}

// String implements the fmt.Stringer interface.
func (s Scope) String() string {
	return strings.Join(s, " ")
}

// MarshalJSON implements the json.Marshaler interface.
func (s Scope) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.String())
}
