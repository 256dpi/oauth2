package server

import (
	"time"

	"github.com/gonfire/oauth2"
	"github.com/gonfire/oauth2/delegate"
	"github.com/gonfire/oauth2/hmacsha"
)

type manager struct{}

func (m *manager) LookupClient(id string) (delegate.Client, error) {
	c, ok := clients[id]
	if !ok {
		return nil, delegate.ErrNotFound
	}

	return c, nil
}

func (m *manager) LookupResourceOwner(id string) (delegate.ResourceOwner, error) {
	ro, ok := users[id]
	if !ok {
		return nil, delegate.ErrNotFound
	}

	return ro, nil
}

func (m *manager) GrantScope(c delegate.Client, ro delegate.ResourceOwner, scope oauth2.Scope) (oauth2.Scope, error) {
	ok := allowedScope.Includes(scope)
	if !ok {
		return nil, delegate.ErrRejected
	}

	return scope, nil
}

func (m *manager) IssueAccessToken(c delegate.Client, ro delegate.ResourceOwner, scope oauth2.Scope) (string, int, error) {
	// generate new token
	t := hmacsha.MustGenerate(secret, 32)

	// set resource owner id if present
	roID := ""
	if ro != nil {
		roID = ro.ID()
	}

	// save access token
	addToken(accessTokens, &token{
		clientID:        c.ID(),
		resourceOwnerID: roID,
		signature:       t.SignatureString(),
		expiresAt:       time.Now().Add(tokenLifespan),
		scope:           scope,
	})

	return t.String(), int(tokenLifespan / time.Second), nil
}

func (m *manager) ParseConsent(r *oauth2.AuthorizationRequest) (string, string, oauth2.Scope, error) {
	username := r.HTTP.PostForm.Get("username")
	password := r.HTTP.PostForm.Get("password")

	return username, password, r.Scope, nil
}

func (m *manager) LookupAuthorizationCode(code string) (delegate.AuthorizationCode, error) {
	t, err := hmacsha.Parse(secret, code)
	if err != nil {
		return nil, delegate.ErrMalformed
	}

	ac, ok := authorizationCodes[t.SignatureString()]
	if !ok {
		return nil, delegate.ErrNotFound
	}

	return ac, nil
}

func (m *manager) IssueAuthorizationCode(c delegate.Client, ro delegate.ResourceOwner, scope oauth2.Scope, uri string) (string, error) {
	// generate new token
	t := hmacsha.MustGenerate(secret, 32)

	// set resource owner id if present
	roID := ""
	if ro != nil {
		roID = ro.ID()
	}

	// save access token
	addToken(authorizationCodes, &token{
		clientID:        c.ID(),
		resourceOwnerID: roID,
		signature:       t.SignatureString(),
		expiresAt:       time.Now().Add(authorizationCodeLifespan),
		scope:           scope,
		redirectURI:     uri,
	})

	return t.String(), nil
}

func (m *manager) RemoveAuthorizationCode(code string) error {
	t, err := hmacsha.Parse(secret, code)
	if err != nil {
		return err
	}

	delete(authorizationCodes, t.SignatureString())

	return nil
}

func (m *manager) LookupRefreshToken(token string) (delegate.RefreshToken, error) {
	t, err := hmacsha.Parse(secret, token)
	if err != nil {
		return nil, delegate.ErrMalformed
	}

	rt, ok := refreshTokens[t.SignatureString()]
	if !ok {
		return nil, delegate.ErrNotFound
	}

	return rt, nil
}

func (m *manager) IssueRefreshToken(c delegate.Client, ro delegate.ResourceOwner, scope oauth2.Scope) (string, error) {
	// generate new token
	t := hmacsha.MustGenerate(secret, 32)

	// set resource owner id if present
	roID := ""
	if ro != nil {
		roID = ro.ID()
	}

	// save refresh token
	addToken(refreshTokens, &token{
		clientID:        c.ID(),
		resourceOwnerID: roID,
		signature:       t.SignatureString(),
		expiresAt:       time.Now().Add(refreshTokenLifespan),
		scope:           scope,
	})

	return t.String(), nil
}

func (m *manager) RemoveRefreshToken(token string) error {
	t, err := hmacsha.Parse(secret, token)
	if err != nil {
		return err
	}

	delete(refreshTokens, t.SignatureString())

	return nil
}
