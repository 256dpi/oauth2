package client

import (
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/256dpi/oauth2"
)

// Error represents basic request errors.
type Error struct {
	Status int
	Body   string
}

// Error implements the error interface.
func (e *Error) Error() string {
	return fmt.Sprintf("request error (%d): %s", e.Status, e.Body)
}

// ParseRequestError will try to parse an oauth2.Error from the provided
// response. It will fallback to an Error containing the servers response.
func ParseRequestError(res *http.Response) error {
	// read full body
	data, _ := readAll(res, 512)

	// check oauth error
	var oauthError oauth2.Error
	if json.Unmarshal(data, &oauthError) == nil {
		oauthError.Status = res.StatusCode
		return &oauthError
	}

	return &Error{
		Status: res.StatusCode,
		Body:   string(data),
	}
}
