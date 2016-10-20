package delegate

import "github.com/gonfire/oauth2"

func AuthorizeImplicitGrant(d Delegate, r *oauth2.AuthorizationRequest) (*oauth2.TokenResponse, error) {
	return nil, nil
}

func AuthorizeAuthorizationCodeGrant(d Delegate, r *oauth2.AuthorizationRequest) (*oauth2.CodeResponse, error) {
	return nil, nil
}
