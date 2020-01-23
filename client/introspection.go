package client

import (
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/256dpi/oauth2"
)

// IntrospectionRequestValues will return the form values for the provided request.
func IntrospectionRequestValues(r oauth2.IntrospectionRequest) url.Values {
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
func BuildIntrospectionRequest(uri string, r oauth2.IntrospectionRequest) (*http.Request, error) {
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
func ParseIntrospectionResponse(res *http.Response, limit int64) (*oauth2.IntrospectionResponse, error) {
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
	var irs oauth2.IntrospectionResponse
	err = json.Unmarshal(data, &irs)
	if err != nil {
		return nil, err
	}

	return &irs, nil
}
