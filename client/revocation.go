package client

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/256dpi/oauth2/revocation"
)

// RevocationRequestValues will return the form values for the provided request.
func RevocationRequestValues(r revocation.Request) url.Values {
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
func BuildRevocationRequest(uri string, r revocation.Request) (*http.Request, error) {
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
