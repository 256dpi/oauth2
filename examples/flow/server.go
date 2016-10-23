// Package flow implements a complete example authentication server using the
// flow package to abstract the common protocol flows.
package flow

import (
	"net/http"
	"time"

	"github.com/gonfire/oauth2"
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

func (m *manager) ObtainConsent(w http.ResponseWriter, ar *oauth2.AuthorizationRequest) *flow.Consent {
	if ar.HTTP.Method == "GET" {
		w.Write([]byte("This authentication server does not provide an authorization form.\n" +
			"Please submit the resource owners username and password in the request body."))
		return nil
	}

	return &flow.Consent{
		ResourceOwnerID:     ar.HTTP.PostForm.Get("username"),
		ResourceOwnerSecret: ar.HTTP.PostForm.Get("password"),
		RequestedScope:      ar.Scope,
	}
}

func (m *manager) ValidateFlow(f flow.Flow, c flow.Client) error {
	return nil
}

func newHandler(m *manager) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/token", flow.ManagedTokenEndpoint(m, nil))
	mux.HandleFunc("/oauth2/authorize", flow.ManagedAuthorizationEndpoint(m, nil))
	mux.HandleFunc("/api/protected", protectedResource(m))
	return mux
}

func protectedResource(m *manager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// authorize resource access
		_, err := flow.AuthorizeResourceAccess(m, r, requiredScope)
		if err != nil {
			flow.HandleError(w, err)
			return
		}

		w.Write([]byte("OK"))
	}
}
