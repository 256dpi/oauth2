package delegate

import (
	"github.com/gonfire/oauth2"
	"net/http"
)

func ProcessAuthorizationRequest(d Delegate, r *http.Request) (*oauth2.AuthorizationRequest, Client, error) {
	// parse authorization request
	req, err := oauth2.ParseAuthorizationRequest(r)
	if err != nil {
		return nil, nil, err
	}

	// make sure the response type is known
	if !oauth2.KnownResponseType(req.ResponseType) {
		return nil, nil, oauth2.InvalidRequest(req.State, "Unknown response type")
	}

	// load client
	client, err := d.LookupClient(req.ClientID)
	if err == ErrNotFound {
		return nil, nil, oauth2.InvalidClient(req.State, "Unknown client")
	} else if err != nil {
		return nil, nil, oauth2.ServerError(req.State, "Failed to lookup client")
	}

	// validate redirect uri
	if !client.ValidRedirectURI(req.RedirectURI) {
		return nil, nil, oauth2.InvalidRequest(req.State, "Invalid redirect URI")
	}

	return req, client, nil
}

func AuthorizeImplicitGrant(d Delegate, r *oauth2.AuthorizationRequest) (*oauth2.TokenResponse, error) {
	return nil, nil
}

func AuthorizeAuthorizationCodeGrant(d Delegate, r *oauth2.AuthorizationRequest) (*oauth2.CodeResponse, error) {
	return nil, nil
}
