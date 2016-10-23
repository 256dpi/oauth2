package flow

import (
	"net/http"

	"github.com/gonfire/oauth2"
	"github.com/gonfire/oauth2/bearer"
)

// ProcessAuthorizationRequest will parse the specified request as a
// authorization request and perform some basic validation.
func ProcessAuthorizationRequest(d Delegate, r *http.Request) (*oauth2.AuthorizationRequest, Client, Error) {
	// parse authorization request
	ar, err := oauth2.ParseAuthorizationRequest(r)
	if err != nil {
		return nil, nil, &OAuth2Error{
			Error: err,
		}
	}

	// make sure the response type is known
	if !oauth2.KnownResponseType(ar.ResponseType) {
		return nil, nil, &OAuth2Error{
			Error: oauth2.InvalidRequest(ar.State, "Unknown response type"),
		}
	}

	// load client
	client, err := d.LookupClient(ar.ClientID)
	if err == ErrNotFound {
		return nil, nil, &OAuth2Error{
			Error: oauth2.InvalidClient(ar.State, "Unknown client"),
		}
	} else if err != nil {
		return nil, nil, &OAuth2Error{
			Source: err,
			Error:  oauth2.ServerError(ar.State, "Failed to lookup client"),
		}
	}

	// validate redirect uri
	if !client.ValidRedirectURI(ar.RedirectURI) {
		return nil, nil, &OAuth2Error{
			Error: oauth2.InvalidRequest(ar.State, "Invalid redirect URI"),
		}
	}

	return ar, client, nil
}

// AuthorizeImplicitGrant will handle the implicit grant.
func AuthorizeImplicitGrant(d Delegate, c Client, r *oauth2.AuthorizationRequest) (*oauth2.TokenResponse, Error) {
	// parse consent
	roID, roSecret, scope, err := d.ParseConsent(r)
	if err != nil {
		return nil, &OAuth2Error{
			Source:      err,
			Error:       oauth2.ServerError(r.State, "Failed to parse consent"),
			RedirectURI: r.RedirectURI,
			UseFragment: true,
		}
	}

	// lookup resource owner
	ro, err := d.LookupResourceOwner(roID)
	if err == ErrNotFound {
		return nil, &OAuth2Error{
			Error:       oauth2.AccessDenied(r.State, "Unknown resource owner"),
			RedirectURI: r.RedirectURI,
			UseFragment: true,
		}
	} else if err != nil {
		return nil, &OAuth2Error{
			Source:      err,
			Error:       oauth2.ServerError(r.State, "Failed to lookup resource owner"),
			RedirectURI: r.RedirectURI,
			UseFragment: true,
		}
	}

	// authenticate resource owner
	if !ro.ValidSecret(roSecret) {
		return nil, &OAuth2Error{
			Error:       oauth2.AccessDenied(r.State, "Unknown resource owner"),
			RedirectURI: r.RedirectURI,
			UseFragment: true,
		}
	}

	// grant scope
	grantedScope, err := d.GrantScope(c, ro, scope)
	if err == ErrRejected {
		return nil, &OAuth2Error{
			Error:       oauth2.InvalidScope(r.State, "The scope has not been granted"),
			RedirectURI: r.RedirectURI,
			UseFragment: true,
		}
	} else if err != nil {
		return nil, &OAuth2Error{
			Source:      err,
			Error:       oauth2.ServerError(r.State, "Failed to grant scope"),
			RedirectURI: r.RedirectURI,
			UseFragment: true,
		}
	}

	// issue access token
	accessToken, expiresIn, err := d.IssueAccessToken(c, ro, grantedScope)
	if err != nil {
		return nil, &OAuth2Error{
			Source:      err,
			Error:       oauth2.ServerError(r.State, "Failed to issue access token"),
			RedirectURI: r.RedirectURI,
			UseFragment: true,
		}
	}

	// prepare response
	res := bearer.NewTokenResponse(accessToken, expiresIn)

	// set granted scope
	res.Scope = grantedScope

	// set state
	res.State = r.State

	return res, nil
}

// HandleAuthorizationCodeGrantAuthorization will authorize the authorization
// code grant.
func HandleAuthorizationCodeGrantAuthorization(d AuthorizationCodeDelegate, c Client, r *oauth2.AuthorizationRequest) (*oauth2.CodeResponse, Error) {
	// parse consent
	roID, roSecret, scope, err := d.ParseConsent(r)
	if err != nil {
		return nil, &OAuth2Error{
			Source:      err,
			Error:       oauth2.ServerError(r.State, "Failed to parse consent"),
			RedirectURI: r.RedirectURI,
		}
	}

	// lookup resource owner
	ro, err := d.LookupResourceOwner(roID)
	if err == ErrNotFound {
		return nil, &OAuth2Error{
			Error:       oauth2.AccessDenied(r.State, "Unknown resource owner"),
			RedirectURI: r.RedirectURI,
		}
	} else if err != nil {
		return nil, &OAuth2Error{
			Source:      err,
			Error:       oauth2.ServerError(r.State, "Failed to lookup resource owner"),
			RedirectURI: r.RedirectURI,
		}
	}

	// authenticate resource owner
	if !ro.ValidSecret(roSecret) {
		return nil, &OAuth2Error{
			Error:       oauth2.AccessDenied(r.State, "Unknown resource owner"),
			RedirectURI: r.RedirectURI,
		}
	}

	// grant scope
	grantedScope, err := d.GrantScope(c, ro, scope)
	if err == ErrRejected {
		return nil, &OAuth2Error{
			Error:       oauth2.InvalidScope(r.State, "The scope has not been granted"),
			RedirectURI: r.RedirectURI,
		}
	} else if err != nil {
		return nil, &OAuth2Error{
			Source:      err,
			Error:       oauth2.ServerError(r.State, "Failed to grant scope"),
			RedirectURI: r.RedirectURI,
		}
	}

	// issue authorization code
	authorizationCode, err := d.IssueAuthorizationCode(c, ro, grantedScope, r.RedirectURI)
	if err != nil {
		return nil, &OAuth2Error{
			Source:      err,
			Error:       oauth2.ServerError(r.State, "Failed to issue access token"),
			RedirectURI: r.RedirectURI,
		}
	}

	// prepare response
	res := oauth2.NewCodeResponse(authorizationCode)

	// set state
	res.State = r.State

	return res, nil
}
