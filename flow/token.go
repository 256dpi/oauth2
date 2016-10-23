package flow

import (
	"net/http"
	"time"

	"github.com/gonfire/oauth2"
	"github.com/gonfire/oauth2/bearer"
)

// ProcessTokenRequest will parse the specified request as a token request and
// perform some basic validation.
func ProcessTokenRequest(d Delegate, r *http.Request) (*oauth2.TokenRequest, Client, *Error) {
	// parse token request
	req, err := oauth2.ParseTokenRequest(r)
	if err != nil {
		return nil, nil, WrapError(nil, err)
	}

	// make sure the grant type is known
	if !oauth2.KnownGrantType(req.GrantType) {
		return nil, nil, WrapError(nil, oauth2.InvalidRequest(oauth2.NoState, "Unknown grant type"))
	}

	// load client
	client, err := d.LookupClient(req.ClientID)
	if err == ErrNotFound {
		return nil, nil, WrapError(nil, oauth2.InvalidClient(oauth2.NoState, "Unknown client"))
	} else if err != nil {
		return nil, nil, WrapError(err, oauth2.ServerError(oauth2.NoState, "Failed to lookup client"))
	}

	// authenticate client if confidential
	if client.Confidential() && !client.ValidSecret(req.ClientSecret) {
		return nil, nil, WrapError(nil, oauth2.InvalidClient(oauth2.NoState, "Unknown client"))
	}

	return req, client, nil
}

// HandlePasswordGrant will handle the resource owner password credentials grant.
func HandlePasswordGrant(d Delegate, c Client, r *oauth2.TokenRequest) (*oauth2.TokenResponse, *Error) {
	// get resource owner
	ro, err := d.LookupResourceOwner(r.Username)
	if err == ErrNotFound {
		return nil, WrapError(nil, oauth2.AccessDenied(oauth2.NoState, "Unknown resource owner"))
	} else if err != nil {
		return nil, WrapError(err, oauth2.ServerError(oauth2.NoState, "Failed to lookup resource owner"))
	}

	// authenticate resource owner
	if !ro.ValidSecret(r.Password) {
		return nil, WrapError(nil, oauth2.AccessDenied(oauth2.NoState, "Unknown resource owner"))
	}

	// grant scope
	grantedScope, err := d.GrantScope(c, ro, r.Scope)
	if err == ErrRejected {
		return nil, WrapError(nil, oauth2.InvalidScope(oauth2.NoState, "The scope has not been granted"))
	} else if err != nil {
		return nil, WrapError(err, oauth2.ServerError(oauth2.NoState, "Failed to grant scope"))
	}

	// issue tokens
	res, wrappedErr := BuildTokenResponse(d, c, ro, grantedScope)
	if err != nil {
		return nil, wrappedErr
	}

	return res, nil
}

// HandleClientCredentialsGrant will handle the client credentials grant for.
func HandleClientCredentialsGrant(d Delegate, c Client, r *oauth2.TokenRequest) (*oauth2.TokenResponse, *Error) {
	// grant scope
	grantedScope, err := d.GrantScope(c, nil, r.Scope)
	if err == ErrRejected {
		return nil, WrapError(nil, oauth2.InvalidScope(oauth2.NoState, "The scope has not been granted"))
	} else if err != nil {
		return nil, WrapError(err, oauth2.ServerError(oauth2.NoState, "Failed to grant scope"))
	}

	// issue tokens
	res, wrappedErr := BuildTokenResponse(d, c, nil, grantedScope)
	if err != nil {
		return nil, wrappedErr
	}

	return res, nil
}

// HandleAuthorizationCodeGrant will handle the authorization code grant.
func HandleAuthorizationCodeGrant(d AuthorizationCodeDelegate, c Client, r *oauth2.TokenRequest) (*oauth2.TokenResponse, *Error) {
	// get authorization code
	ac, err := d.LookupAuthorizationCode(r.Code)
	if err == ErrMalformed {
		return nil, WrapError(nil, oauth2.InvalidRequest(oauth2.NoState, "Malformed authorization code"))
	} else if err == ErrNotFound {
		return nil, WrapError(nil, oauth2.InvalidGrant(oauth2.NoState, "Unknown authorization code"))
	} else if err != nil {
		return nil, WrapError(err, oauth2.ServerError(oauth2.NoState, "Failed to lookup authorization code"))
	}

	// validate expiration
	if ac.ExpiresAt().Before(time.Now()) {
		return nil, WrapError(nil, oauth2.InvalidGrant(oauth2.NoState, "Expired authorization code"))
	}

	// validate redirect uri
	if ac.RedirectURI() != r.RedirectURI {
		return nil, WrapError(nil, oauth2.InvalidGrant(oauth2.NoState, "Changed redirect uri"))
	}

	// validate ownership
	if ac.ClientID() != c.ID() {
		return nil, WrapError(nil, oauth2.InvalidGrant(oauth2.NoState, "Invalid authorization code ownership"))
	}

	// prepare resource owner
	var ro ResourceOwner

	// validate resource owner by lookup if present
	if ac.ResourceOwnerID() != "" {
		ro, err = d.LookupResourceOwner(ac.ResourceOwnerID())
		if err == ErrNotFound {
			return nil, WrapError(err, oauth2.ServerError(oauth2.NoState, "Expected to find resource owner"))
		} else if err != nil {
			return nil, WrapError(err, oauth2.ServerError(oauth2.NoState, "Failed to lookup resource owner"))
		}
	}

	// issue tokens
	res, wrappedErr := BuildTokenResponse(d, c, ro, ac.Scope())
	if err != nil {
		return nil, wrappedErr
	}

	// remove used authorization code
	err = d.RemoveAuthorizationCode(ac)
	if err != nil {
		return nil, WrapError(err, oauth2.ServerError(oauth2.NoState, "Failed to remove authorization code"))
	}

	return res, nil
}

// HandleRefreshTokenGrant will handle the refresh token grant.
func HandleRefreshTokenGrant(d RefreshTokenDelegate, c Client, r *oauth2.TokenRequest) (*oauth2.TokenResponse, *Error) {
	// get refresh token
	rt, err := d.LookupRefreshToken(r.RefreshToken)
	if err == ErrMalformed {
		return nil, WrapError(nil, oauth2.InvalidRequest(oauth2.NoState, "Malformed refresh token"))
	} else if err == ErrNotFound {
		return nil, WrapError(nil, oauth2.InvalidGrant(oauth2.NoState, "Unknown refresh token"))
	} else if err != nil {
		return nil, WrapError(err, oauth2.ServerError(oauth2.NoState, "Failed to lookup refresh token"))
	}

	// validate expiration
	if rt.ExpiresAt().Before(time.Now()) {
		return nil, WrapError(nil, oauth2.InvalidGrant(oauth2.NoState, "Expired refresh token"))
	}

	// inherit scope from stored refresh token
	if r.Scope.Empty() {
		r.Scope = rt.Scope()
	}

	// validate scope
	if !rt.Scope().Includes(r.Scope) {
		return nil, WrapError(nil, oauth2.InvalidScope(oauth2.NoState, "New scope exceeds granted scope"))
	}

	// validate client ownership
	if rt.ClientID() != c.ID() {
		return nil, WrapError(nil, oauth2.InvalidGrant(oauth2.NoState, "Invalid refresh token ownership"))
	}

	// prepare resource owner
	var ro ResourceOwner

	// validate resource owner by lookup if present
	if rt.ResourceOwnerID() != "" {
		ro, err = d.LookupResourceOwner(rt.ResourceOwnerID())
		if err == ErrNotFound {
			return nil, WrapError(err, oauth2.ServerError(oauth2.NoState, "Expected to find resource owner"))
		} else if err != nil {
			return nil, WrapError(err, oauth2.ServerError(oauth2.NoState, "Failed to lookup resource owner"))
		}
	}

	// issue tokens
	res, wrappedErr := BuildTokenResponse(d, c, ro, r.Scope)
	if err != nil {
		return nil, wrappedErr
	}

	// remove used refresh token
	err = d.RemoveRefreshToken(rt)
	if err != nil {
		return nil, WrapError(err, oauth2.ServerError(oauth2.NoState, "Failed to remove refresh token"))
	}

	return res, nil
}

// BuildTokenResponse constructs a token response for the specified client and
// resource owner by issuing an access and refresh token with the specified scope.
//
// Note: The function will determine on runtime if the specified delegate
// is able to issue refresh tokens. If the delegate is capable of issuing refresh
// tokens it will always issue a refresh token. This means that the function
// should not be used to build token responses for the authorization endpoint.
func BuildTokenResponse(d Delegate, c Client, ro ResourceOwner, scope oauth2.Scope) (*oauth2.TokenResponse, *Error) {
	// issue access token
	accessToken, expiresIn, err := d.IssueAccessToken(c, ro, scope)
	if err != nil {
		return nil, WrapError(err, oauth2.ServerError(oauth2.NoState, "Failed to issue access token"))
	}

	// prepare response
	res := bearer.NewTokenResponse(accessToken, expiresIn)

	// set granted scope
	res.Scope = scope

	// issue refresh token if available and implemented
	rtd, ok := d.(RefreshTokenDelegate)
	if ok {
		refreshToken, err := rtd.IssueRefreshToken(c, ro, scope)
		if err != nil {
			return nil, WrapError(err, oauth2.ServerError(oauth2.NoState, "Failed to issue refresh token"))
		}

		// set refresh token
		res.RefreshToken = refreshToken
	}

	return res, nil
}
