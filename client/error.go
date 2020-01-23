package client

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"

	"github.com/256dpi/oauth2"
)

// ParseRequestError will try to parse an oauth2.Error from the provided
// response. It will fallback to an error containing the response status.
func ParseRequestError(res *http.Response, limit int64) error {
	// read full body
	data, _ := ioutil.ReadAll(io.LimitReader(res.Body, limit))

	// check oauth error
	var oauthError oauth2.Error
	if json.Unmarshal(data, &oauthError) == nil {
		oauthError.Status = res.StatusCode
		return &oauthError
	}

	return fmt.Errorf("unexpected response: %s", res.Status)
}
