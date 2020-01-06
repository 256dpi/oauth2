package client

import (
	"encoding/json"
	"fmt"
	"mime"
	"net/http"
	"net/url"
	"strings"

	"github.com/256dpi/oauth2"
)

// TokenRequestValues will return the form values for the provided request.
func TokenRequestValues(r oauth2.TokenRequest) url.Values {
	// prepare slice
	slice := []string{
		r.GrantType,
		r.Scope.String(),
		r.Username,
		r.Password,
		r.RefreshToken,
		url.QueryEscape(r.RedirectURI),
		r.Code,
	}

	// prepare values
	values := make(url.Values, len(slice))

	// set grant type if available
	if r.GrantType != "" {
		values["grant_type"] = slice[0:1]
	}

	// set scope if available
	if len(r.Scope) != 0 {
		values["scope"] = slice[1:2]
	}

	// set username if available
	if r.Username != "" {
		values["username"] = slice[2:3]
	}

	// set password if available
	if r.Password != "" {
		values["password"] = slice[3:4]
	}

	// set refresh token if available
	if r.RefreshToken != "" {
		values["refresh_token"] = slice[4:5]
	}

	// set redirect uri if available
	if r.RedirectURI != "" {
		values["redirect_uri"] = slice[5:6]
	}

	// set code if available
	if r.Code != "" {
		values["code"] = slice[6:7]
	}

	return values
}

// BuildTokenRequest will build a request from the provided data.
func BuildTokenRequest(uri string, r oauth2.TokenRequest) (*http.Request, error) {
	// prepare body
	body := strings.NewReader(TokenRequestValues(r).Encode())

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

// ParseTokenResponse will parse the provided response.
func ParseTokenResponse(res *http.Response) (*oauth2.TokenResponse, error) {
	// read response
	data, err := readAll(res, 1024)
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

	// decode token response
	var trs oauth2.TokenResponse
	err = json.Unmarshal(data, &trs)
	if err != nil {
		return nil, err
	}

	return &trs, nil
}
