// Package flow implements a complete example authentication server using the
// flow package to abstract the common protocol flows.
package flow

import (
	"net/http"
	"time"

	"github.com/gonfire/oauth2"
	"github.com/gonfire/oauth2/bearer"
	"github.com/gonfire/oauth2/flow"
	"github.com/gonfire/oauth2/hmacsha"
	"golang.org/x/crypto/bcrypt"
)

var secret = []byte("abcd1234abcd1234")

var tokenLifespan = time.Hour
var refreshTokenLifespan = 7 * 24 * time.Hour
var authorizationCodeLifespan = 10 * time.Minute

var allowedScope = oauth2.ParseScope("foo bar")
var requiredScope = oauth2.ParseScope("foo")

type owner struct {
	id           string
	secret       []byte
	redirectURI  string
	confidential bool
}

func (o *owner) ID() string {
	return o.id
}

func (o *owner) Confidential() bool {
	return o.confidential
}

func (o *owner) ValidSecret(pw string) bool {
	return sameHash(o.secret, pw)
}

func (o *owner) ValidRedirectURI(uri string) bool {
	return o.redirectURI == uri
}

var clients = map[string]*owner{}
var users = map[string]*owner{}

type credential struct {
	clientID        string
	resourceOwnerID string
	signature       string
	expiresAt       time.Time
	scope           oauth2.Scope
	redirectURI     string
}

func (t *credential) ClientID() string {
	return t.clientID
}

func (t *credential) ResourceOwnerID() string {
	return t.resourceOwnerID
}

func (t *credential) ExpiresAt() time.Time {
	return t.expiresAt
}

func (t *credential) Scope() oauth2.Scope {
	return t.scope
}

func (t *credential) RedirectURI() string {
	return t.redirectURI
}

var accessTokens = make(map[string]*credential)
var refreshTokens = make(map[string]*credential)
var authorizationCodes = make(map[string]*credential)

func addOwner(list map[string]*owner, o *owner) *owner {
	list[o.id] = o
	return o
}

func addCredential(list map[string]*credential, t *credential) *credential {
	list[t.signature] = t
	return t
}

func sameHash(hash []byte, str string) bool {
	return bcrypt.CompareHashAndPassword(hash, []byte(str)) == nil
}

type manager struct{}

func (m *manager) LookupClient(id string) (flow.Client, error) {
	c, ok := clients[id]
	if !ok {
		return nil, flow.ErrNotFound
	}

	return c, nil
}

func (m *manager) LookupResourceOwner(id string) (flow.ResourceOwner, error) {
	ro, ok := users[id]
	if !ok {
		return nil, flow.ErrNotFound
	}

	return ro, nil
}

func (m *manager) GrantScope(c flow.Client, ro flow.ResourceOwner, scope oauth2.Scope) (oauth2.Scope, error) {
	ok := allowedScope.Includes(scope)
	if !ok {
		return nil, flow.ErrRejected
	}

	return scope, nil
}

func (m *manager) LookupAccessToken(key string) (flow.AccessToken, error) {
	t, err := hmacsha.Parse(secret, key)
	if err != nil {
		return nil, flow.ErrMalformed
	}

	at, ok := accessTokens[t.SignatureString()]
	if !ok {
		return nil, flow.ErrNotFound
	}

	return at, nil
}

func (m *manager) IssueAccessToken(c flow.Client, ro flow.ResourceOwner, scope oauth2.Scope) (string, int, error) {
	// generate new token
	t := hmacsha.MustGenerate(secret, 32)

	// set resource owner id if present
	roID := ""
	if ro != nil {
		roID = ro.ID()
	}

	// save access token
	addCredential(accessTokens, &credential{
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

func (m *manager) LookupAuthorizationCode(code string) (flow.AuthorizationCode, error) {
	t, err := hmacsha.Parse(secret, code)
	if err != nil {
		return nil, flow.ErrMalformed
	}

	ac, ok := authorizationCodes[t.SignatureString()]
	if !ok {
		return nil, flow.ErrNotFound
	}

	return ac, nil
}

func (m *manager) IssueAuthorizationCode(c flow.Client, ro flow.ResourceOwner, scope oauth2.Scope, uri string) (string, error) {
	// generate new token
	t := hmacsha.MustGenerate(secret, 32)

	// set resource owner id if present
	roID := ""
	if ro != nil {
		roID = ro.ID()
	}

	// save access token
	addCredential(authorizationCodes, &credential{
		clientID:        c.ID(),
		resourceOwnerID: roID,
		signature:       t.SignatureString(),
		expiresAt:       time.Now().Add(authorizationCodeLifespan),
		scope:           scope,
		redirectURI:     uri,
	})

	return t.String(), nil
}

func (m *manager) RemoveAuthorizationCode(ac flow.AuthorizationCode) error {
	delete(authorizationCodes, ac.(*credential).signature)
	return nil
}

func (m *manager) LookupRefreshToken(token string) (flow.RefreshToken, error) {
	t, err := hmacsha.Parse(secret, token)
	if err != nil {
		return nil, flow.ErrMalformed
	}

	rt, ok := refreshTokens[t.SignatureString()]
	if !ok {
		return nil, flow.ErrNotFound
	}

	return rt, nil
}

func (m *manager) IssueRefreshToken(c flow.Client, ro flow.ResourceOwner, scope oauth2.Scope) (string, error) {
	// generate new token
	t := hmacsha.MustGenerate(secret, 32)

	// set resource owner id if present
	roID := ""
	if ro != nil {
		roID = ro.ID()
	}

	// save refresh token
	addCredential(refreshTokens, &credential{
		clientID:        c.ID(),
		resourceOwnerID: roID,
		signature:       t.SignatureString(),
		expiresAt:       time.Now().Add(refreshTokenLifespan),
		scope:           scope,
	})

	return t.String(), nil
}

func (m *manager) RemoveRefreshToken(rt flow.RefreshToken) error {
	delete(refreshTokens, rt.(*credential).signature)
	return nil
}

func newHandler(m *manager) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", tokenEndpoint(m))
	mux.HandleFunc("/oauth2/authorize", authorizationEndpoint(m))
	mux.HandleFunc("/api/protected", protectedResource(m))
	return mux
}

func protectedResource(m *manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// authorize resource access
		_, err := flow.AuthorizeResourceAccess(m, r, requiredScope)
		if err != nil {
			bearer.WriteError(w, err)
			return
		}

		w.Write([]byte("OK"))
	}
}

func authorizationEndpoint(m *manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// process authorization request
		ar, c, err := flow.ProcessAuthorizationRequest(m, r)
		if err != nil {
			oauth2.WriteError(w, err)
			return
		}

		// show info notice on a GET request
		if r.Method == "GET" {
			w.Write([]byte("This authentication server does not provide an authorization form.\n" +
				"Please submit the resource owners username and password in the request body."))
			return
		}

		// triage based on response type
		switch ar.ResponseType {
		case oauth2.TokenResponseType:
			// authorize implicit grant
			res, err := flow.AuthorizeImplicitGrant(m, c, ar)
			if err != nil {
				oauth2.RedirectError(w, ar.RedirectURI, true, err)
				return
			}

			// redirect response
			oauth2.RedirectTokenResponse(w, ar.RedirectURI, res)
		case oauth2.CodeResponseType:
			// authorize authorization code grant
			res, err := flow.HandleAuthorizationCodeGrantAuthorization(m, c, ar)
			if err != nil {
				oauth2.RedirectError(w, ar.RedirectURI, false, err)
				return
			}

			// redirect response
			oauth2.RedirectCodeResponse(w, ar.RedirectURI, res)
		}
	}
}

func tokenEndpoint(m *manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// process token request
		tr, c, err := flow.ProcessTokenRequest(m, r)
		if err != nil {
			oauth2.WriteError(w, err)
			return
		}

		switch tr.GrantType {
		case oauth2.PasswordGrantType:
			// handle resource owner password credentials grant
			res, err := flow.HandlePasswordGrant(m, c, tr)
			if err != nil {
				oauth2.WriteError(w, err)
				return
			}

			// write response
			oauth2.WriteTokenResponse(w, res)
		case oauth2.ClientCredentialsGrantType:
			// handle client credentials grant
			res, err := flow.HandleClientCredentialsGrant(m, c, tr)
			if err != nil {
				oauth2.WriteError(w, err)
				return
			}

			// write response
			oauth2.WriteTokenResponse(w, res)
		case oauth2.AuthorizationCodeGrantType:
			// handle client credentials grant
			res, err := flow.HandleAuthorizationCodeGrant(m, c, tr)
			if err != nil {
				oauth2.WriteError(w, err)
				return
			}

			// write response
			oauth2.WriteTokenResponse(w, res)
		case oauth2.RefreshTokenGrantType:
			// handle refresh token grant
			res, err := flow.HandleRefreshTokenGrant(m, c, tr)
			if err != nil {
				oauth2.WriteError(w, err)
				return
			}

			// write response
			oauth2.WriteTokenResponse(w, res)
		}
	}
}
