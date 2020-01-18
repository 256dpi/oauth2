// Package oauth2 provides structures and functions to implement OAuth2
// compatible authentication servers.
//
// The library can be used standalone or with any framework as it is built on
// top of the standard Go http library.
package oauth2

import (
	"encoding/json"
	"net/http"
	"net/url"
)

// The known OAuth2 grant types.
const (
	PasswordGrantType          = "password"
	ClientCredentialsGrantType = "client_credentials"
	AuthorizationCodeGrantType = "authorization_code"
	RefreshTokenGrantType      = "refresh_token"
)

// KnownGrantType returns true if the grant type is a known grant type
// (e.g. password, client credentials, authorization code or refresh token).
func KnownGrantType(str string) bool {
	switch str {
	case PasswordGrantType,
		ClientCredentialsGrantType,
		AuthorizationCodeGrantType,
		RefreshTokenGrantType:
		return true
	}

	return false
}

// The known OAuth2 response types.
const (
	TokenResponseType = "token"
	CodeResponseType  = "code"
)

// KnownResponseType returns true if the response type is a known response type
// (e.g. token or code).
func KnownResponseType(str string) bool {
	switch str {
	case TokenResponseType, CodeResponseType:
		return true
	}

	return false
}

// The known OAuth2 token types.
const (
	AccessToken  = "access_token"
	RefreshToken = "refresh_token"
)

// KnownTokenType returns true if the token type is a known token type
// (e.g. access token or refresh token).
func KnownTokenType(str string) bool {
	switch str {
	case AccessToken,
		RefreshToken:
		return true
	}

	return false
}

// Write will encode the specified object as json and write a response to the
// response writer as specified by the OAuth2 spec.
func Write(w http.ResponseWriter, obj interface{}, status int) error {
	// set required headers
	w.Header().Set("Content-Type", "application/json;charset=UTF-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	// set status
	w.WriteHeader(status)

	// write error document
	err := json.NewEncoder(w).Encode(obj)

	return err
}

// WriteRedirect will either add the specified parameters to the query of the
// specified uri or encode them and it as the fragment as specified by the
// OAuth2 spec.
func WriteRedirect(w http.ResponseWriter, uri string, params map[string]string, useFragment bool) error {
	// parse redirect uri
	redirectURI, err := url.ParseRequestURI(uri)
	if err != nil {
		return err
	}

	// add params to fragment if requested
	if useFragment {
		// prepare fragment
		f := make(url.Values)

		// add parameters
		for k, v := range params {
			f.Add(k, v)
		}

		// encode fragment
		redirectURI.Fragment = f.Encode()
	} else {
		// get current query
		q := redirectURI.Query()

		// add parameters
		for k, v := range params {
			q.Add(k, v)
		}

		// reset query
		redirectURI.RawQuery = q.Encode()
	}

	// set location
	w.Header().Add("Location", redirectURI.String())

	// prevent caching
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")

	// prevent referrer leakage
	w.Header().Set("Referrer-Policy", "origin")

	// write redirect
	w.WriteHeader(http.StatusSeeOther)

	// finish response
	_, err = w.Write(nil)

	return err
}
