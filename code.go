package oauth2

import (
	"net/http"
)

// A CodeResponse is typically constructed after an authorization code request
// has been authenticated to return an authorization code.
type CodeResponse struct {
	Code  string `json:"code"`
	State string `json:"state,omitempty"`

	RedirectURI string `json:"-"`
}

// NewCodeResponse constructs a CodeResponse.
func NewCodeResponse(code, redirectURI, state string) *CodeResponse {
	return &CodeResponse{
		Code:        code,
		State:       state,
		RedirectURI: redirectURI,
	}
}

// Map returns a map of all fields that can be presented to the client. This
// method can be used to construct query parameters or a fragment when
// redirecting the code response.
func (r *CodeResponse) Map() map[string]string {
	m := make(map[string]string)

	// add code
	m["code"] = r.Code

	// add state if present
	if r.State != "" {
		m["state"] = r.State
	}

	return m
}

// WriteCodeResponse will write a redirection based on the specified code
// response to the response writer.
func WriteCodeResponse(w http.ResponseWriter, r *CodeResponse) error {
	return WriteRedirect(w, r.RedirectURI, r.Map(), false)
}
