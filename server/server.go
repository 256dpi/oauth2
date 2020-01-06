// Package server provides a basic in-memory OAuth2 authentication server
// intended for testing purposes. The implementation may be used to as a
// reference or template to build a custom OAuth2 authentication server.
package server

import (
	"net/http"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/256dpi/oauth2"
	"github.com/256dpi/oauth2/bearer"
	"github.com/256dpi/oauth2/hmacsha"
	"github.com/256dpi/oauth2/introspection"
	"github.com/256dpi/oauth2/revocation"
)

// MustHash will hash the specified clear text.
func MustHash(clear string) []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte(clear), bcrypt.MinCost)
	if err != nil {
		panic(err)
	}

	return hash
}

// SameHash verifies if the provided clear text and hash are equal.
func SameHash(hash []byte, clear string) bool {
	return bcrypt.CompareHashAndPassword(hash, []byte(clear)) == nil
}

// Config is used to configure a server.
type Config struct {
	Secret                    []byte
	KeyLength                 int
	AllowedScope              oauth2.Scope
	AccessTokenLifespan       time.Duration
	RefreshTokenLifespan      time.Duration
	AuthorizationCodeLifespan time.Duration
}

// Default will return a default configuration based on the provided parameters.
func Default(secret []byte, allowed oauth2.Scope) Config {
	return Config{
		Secret:                    secret,
		KeyLength:                 16,
		AllowedScope:              allowed,
		AccessTokenLifespan:       time.Hour,
		RefreshTokenLifespan:      7 * 24 * time.Hour,
		AuthorizationCodeLifespan: 10 * time.Minute,
	}
}

// MustGenerate will generate a new token.
func (c Config) MustGenerate() *hmacsha.Token {
	return hmacsha.MustGenerate(c.Secret, c.KeyLength)
}

// Entity represents a client or resource owner.
type Entity struct {
	ID           string
	Secret       []byte
	RedirectURI  string
	Confidential bool
}

// Credential represents an access token, refresh token or authorization code.
type Credential struct {
	ClientID    string
	Username    string
	Signature   string
	ExpiresAt   time.Time
	Scope       oauth2.Scope
	RedirectURI string
	Code        string
	Used        bool
}

// Server implements a basic in-memory OAuth2 authentication server intended for
// testing purposes.
type Server struct {
	config             Config
	clients            map[string]*Entity
	users              map[string]*Entity
	accessTokens       map[string]*Credential
	refreshTokens      map[string]*Credential
	authorizationCodes map[string]*Credential
}

// NewServer creates and returns a new server.
func NewServer(config Config) *Server {
	return &Server{
		config:             config,
		clients:            map[string]*Entity{},
		users:              map[string]*Entity{},
		accessTokens:       map[string]*Credential{},
		refreshTokens:      map[string]*Credential{},
		authorizationCodes: map[string]*Credential{},
	}
}

// AddClient will add the provided client.
func (s *Server) AddClient(client *Entity) {
	s.clients[client.ID] = client
}

// AddUser will add the provided user.
func (s *Server) AddUser(user *Entity) {
	s.users[user.ID] = user
}

// AddAccessToken will add the provided access token.
func (s *Server) AddAccessToken(token *Credential) {
	s.accessTokens[token.Signature] = token
}

// AddRefreshToken will add the provided refresh token.
func (s *Server) AddRefreshToken(token *Credential) {
	s.refreshTokens[token.Signature] = token
}

// AddAuthorizationCode will add the provided authorization code.
func (s *Server) AddAuthorizationCode(code *Credential) {
	s.authorizationCodes[code.Signature] = code
}

// Authorize will authorize the request and require a valid access token. An
// error will already be written to the client if false is returned.
func (s *Server) Authorize(w http.ResponseWriter, r *http.Request, required oauth2.Scope) bool {
	// parse bearer token
	tk, err := bearer.ParseToken(r)
	if err != nil {
		_ = bearer.WriteError(w, err)
		return false
	}

	// parse token
	token, err := hmacsha.Parse(s.config.Secret, tk)
	if err != nil {
		_ = bearer.WriteError(w, bearer.InvalidToken("malformed token"))
		return false
	}

	// get token
	accessToken, found := s.accessTokens[token.SignatureString()]
	if !found {
		_ = bearer.WriteError(w, bearer.InvalidToken("unknown token"))
		return false
	}

	// validate expiration
	if accessToken.ExpiresAt.Before(time.Now()) {
		_ = bearer.WriteError(w, bearer.InvalidToken("expired token"))
		return false
	}

	// validate scope
	if !accessToken.Scope.Includes(required) {
		_ = bearer.WriteError(w, bearer.InsufficientScope(required.String()))
		return false
	}

	return true
}

// ServeHTTP will handle the provided request based on the last path segment
// of the request URL.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// get path
	path := strings.Trim(r.URL.Path, "/")

	// get latest path segment
	idx := strings.LastIndexByte(path, '/')
	if idx > 0 {
		path = path[idx+1:]
	}

	// check path
	switch path {
	case "authorize":
		s.authorizationEndpoint(w, r)
	case "token":
		s.tokenEndpoint(w, r)
	case "introspect":
		s.introspectionEndpoint(w, r)
	case "revoke":
		s.revocationEndpoint(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) authorizationEndpoint(w http.ResponseWriter, r *http.Request) {
	// parse authorization request
	req, err := oauth2.ParseAuthorizationRequest(r)
	if err != nil {
		_ = oauth2.WriteError(w, err)
		return
	}

	// make sure the response type is known
	if !oauth2.KnownResponseType(req.ResponseType) {
		_ = oauth2.WriteError(w, oauth2.InvalidRequest("unknown response type"))
		return
	}

	// get client
	client, found := s.clients[req.ClientID]
	if !found {
		_ = oauth2.WriteError(w, oauth2.InvalidClient("unknown client"))
		return
	}

	// validate redirect uri
	if client.RedirectURI != req.RedirectURI {
		_ = oauth2.WriteError(w, oauth2.InvalidRequest("invalid redirect URI"))
		return
	}

	// show notice for GET requests
	if r.Method == "GET" {
		_, _ = w.Write([]byte("This authentication server does not provide an authorization form.\n" +
			"Please submit the resource owners username and password in a POST request."))
		return
	}

	// read username and password
	username := r.PostForm.Get("username")
	password := r.PostForm.Get("password")

	// triage based on response type
	switch req.ResponseType {
	case oauth2.TokenResponseType:
		s.handleImplicitGrant(w, username, password, req)
	case oauth2.CodeResponseType:
		s.handleAuthorizationCodeGrantAuthorization(w, username, password, req)
	}
}

func (s *Server) handleImplicitGrant(w http.ResponseWriter, username, password string, rq *oauth2.AuthorizationRequest) {
	// validate scope
	if !s.config.AllowedScope.Includes(rq.Scope) {
		_ = oauth2.WriteError(w, oauth2.InvalidScope("").SetRedirect(rq.RedirectURI, rq.State, true))
		return
	}

	// validate user credentials
	owner, found := s.users[username]
	if !found || !SameHash(owner.Secret, password) {
		_ = oauth2.WriteError(w, oauth2.AccessDenied("").SetRedirect(rq.RedirectURI, rq.State, true))
		return
	}

	// issue tokens
	r := s.issueTokens(false, rq.Scope, rq.ClientID, owner.ID, "")

	// redirect token
	r.SetRedirect(rq.RedirectURI, rq.State)

	// write response
	_ = oauth2.WriteTokenResponse(w, r)
}

func (s *Server) handleAuthorizationCodeGrantAuthorization(w http.ResponseWriter, username, password string, rq *oauth2.AuthorizationRequest) {
	// validate scope
	if !s.config.AllowedScope.Includes(rq.Scope) {
		_ = oauth2.WriteError(w, oauth2.InvalidScope("").SetRedirect(rq.RedirectURI, rq.State, false))
		return
	}

	// validate user credentials
	owner, found := s.users[username]
	if !found || !SameHash(owner.Secret, password) {
		_ = oauth2.WriteError(w, oauth2.AccessDenied("").SetRedirect(rq.RedirectURI, rq.State, false))
		return
	}

	// generate new authorization code
	authorizationCode := s.config.MustGenerate()

	// prepare response
	r := oauth2.NewCodeResponse(authorizationCode.String(), rq.RedirectURI, rq.State)

	// save authorization code
	s.authorizationCodes[authorizationCode.SignatureString()] = &Credential{
		ClientID:    rq.ClientID,
		Username:    owner.ID,
		Signature:   authorizationCode.SignatureString(),
		ExpiresAt:   time.Now().Add(s.config.AuthorizationCodeLifespan),
		Scope:       rq.Scope,
		RedirectURI: rq.RedirectURI,
	}

	// write response
	_ = oauth2.WriteCodeResponse(w, r)
}

func (s *Server) tokenEndpoint(w http.ResponseWriter, r *http.Request) {
	// parse token request
	req, err := oauth2.ParseTokenRequest(r)
	if err != nil {
		_ = oauth2.WriteError(w, err)
		return
	}

	// make sure the grant type is known
	if !oauth2.KnownGrantType(req.GrantType) {
		_ = oauth2.WriteError(w, oauth2.InvalidRequest("unknown grant type"))
		return
	}

	// find client
	client, found := s.clients[req.ClientID]
	if !found {
		_ = oauth2.WriteError(w, oauth2.InvalidClient("unknown client"))
		return
	}

	// authenticate client
	if client.Confidential && !SameHash(client.Secret, req.ClientSecret) {
		_ = oauth2.WriteError(w, oauth2.InvalidClient("unknown client"))
		return
	}

	// handle grant type
	switch req.GrantType {
	case oauth2.PasswordGrantType:
		s.handleResourceOwnerPasswordCredentialsGrant(w, req)
	case oauth2.ClientCredentialsGrantType:
		s.handleClientCredentialsGrant(w, req)
	case oauth2.AuthorizationCodeGrantType:
		s.handleAuthorizationCodeGrant(w, req)
	case oauth2.RefreshTokenGrantType:
		s.handleRefreshTokenGrant(w, req)
	}
}

func (s *Server) handleResourceOwnerPasswordCredentialsGrant(w http.ResponseWriter, rq *oauth2.TokenRequest) {
	// authenticate resource owner
	owner, found := s.users[rq.Username]
	if !found || !SameHash(owner.Secret, rq.Password) {
		_ = oauth2.WriteError(w, oauth2.AccessDenied(""))
		return
	}

	// check scope
	if !s.config.AllowedScope.Includes(rq.Scope) {
		_ = oauth2.WriteError(w, oauth2.InvalidScope(""))
		return
	}

	// issue tokens
	r := s.issueTokens(true, rq.Scope, rq.ClientID, rq.Username, "")

	// write response
	_ = oauth2.WriteTokenResponse(w, r)
}

func (s *Server) handleClientCredentialsGrant(w http.ResponseWriter, rq *oauth2.TokenRequest) {
	// check client confidentiality
	if !s.clients[rq.ClientID].Confidential {
		_ = oauth2.WriteError(w, oauth2.InvalidClient("unknown client"))
		return
	}

	// check scope
	if !s.config.AllowedScope.Includes(rq.Scope) {
		_ = oauth2.WriteError(w, oauth2.InvalidScope(""))
		return
	}

	// save tokens
	r := s.issueTokens(true, rq.Scope, rq.ClientID, "", "")

	// write response
	_ = oauth2.WriteTokenResponse(w, r)
}

func (s *Server) handleAuthorizationCodeGrant(w http.ResponseWriter, rq *oauth2.TokenRequest) {
	// parse authorization code
	authorizationCode, err := hmacsha.Parse(s.config.Secret, rq.Code)
	if err != nil {
		_ = oauth2.WriteError(w, oauth2.InvalidRequest(err.Error()))
		return
	}

	// get stored authorization code by signature
	storedAuthorizationCode, found := s.authorizationCodes[authorizationCode.SignatureString()]
	if !found {
		_ = oauth2.WriteError(w, oauth2.InvalidGrant("unknown authorization code"))
		return
	}

	// check if used
	if storedAuthorizationCode.Used {
		// revoke all access tokens
		for key, token := range s.accessTokens {
			if token.Code == authorizationCode.SignatureString() {
				delete(s.accessTokens, key)
			}
		}

		// revoke all refresh tokens
		for key, token := range s.refreshTokens {
			if token.Code == authorizationCode.SignatureString() {
				delete(s.refreshTokens, key)
			}
		}

		_ = oauth2.WriteError(w, oauth2.InvalidGrant("unknown authorization code"))
		return
	}

	// validate expiration
	if storedAuthorizationCode.ExpiresAt.Before(time.Now()) {
		_ = oauth2.WriteError(w, oauth2.InvalidGrant("expired authorization code"))
		return
	}

	// validate ownership
	if storedAuthorizationCode.ClientID != rq.ClientID {
		_ = oauth2.WriteError(w, oauth2.InvalidGrant("invalid authorization code ownership"))
		return
	}

	// validate redirect uri
	if storedAuthorizationCode.RedirectURI != rq.RedirectURI {
		_ = oauth2.WriteError(w, oauth2.InvalidGrant("changed redirect uri"))
		return
	}

	// issue tokens
	r := s.issueTokens(true, storedAuthorizationCode.Scope, rq.ClientID, storedAuthorizationCode.Username, authorizationCode.SignatureString())

	// mark authorization code
	storedAuthorizationCode.Used = true

	// write response
	_ = oauth2.WriteTokenResponse(w, r)
}

func (s *Server) handleRefreshTokenGrant(w http.ResponseWriter, rq *oauth2.TokenRequest) {
	// parse refresh token
	refreshToken, err := hmacsha.Parse(s.config.Secret, rq.RefreshToken)
	if err != nil {
		_ = oauth2.WriteError(w, oauth2.InvalidRequest(err.Error()))
		return
	}

	// get stored refresh token by signature
	storedRefreshToken, found := s.refreshTokens[refreshToken.SignatureString()]
	if !found {
		_ = oauth2.WriteError(w, oauth2.InvalidGrant("unknown refresh token"))
		return
	}

	// validate expiration
	if storedRefreshToken.ExpiresAt.Before(time.Now()) {
		_ = oauth2.WriteError(w, oauth2.InvalidGrant("expired refresh token"))
		return
	}

	// validate ownership
	if storedRefreshToken.ClientID != rq.ClientID {
		_ = oauth2.WriteError(w, oauth2.InvalidGrant("invalid refresh token ownership"))
		return
	}

	// inherit scope from stored refresh token
	if rq.Scope.Empty() {
		rq.Scope = storedRefreshToken.Scope
	}

	// validate scope - a missing scope is always included
	if !storedRefreshToken.Scope.Includes(rq.Scope) {
		_ = oauth2.WriteError(w, oauth2.InvalidScope("scope exceeds the originally granted scope"))
		return
	}

	// issue tokens
	r := s.issueTokens(true, rq.Scope, rq.ClientID, storedRefreshToken.Username, "")

	// delete used refresh token
	delete(s.refreshTokens, refreshToken.SignatureString())

	// write response
	_ = oauth2.WriteTokenResponse(w, r)
}

func (s *Server) revocationEndpoint(w http.ResponseWriter, r *http.Request) {
	// parse authorization request
	req, err := revocation.ParseRequest(r)
	if err != nil {
		_ = oauth2.WriteError(w, err)
		return
	}

	// check token type hint
	if req.TokenTypeHint != "" && !revocation.KnownTokenType(req.TokenTypeHint) {
		_ = oauth2.WriteError(w, revocation.UnsupportedTokenType(""))
		return
	}

	// get client
	client, found := s.clients[req.ClientID]
	if !found {
		_ = oauth2.WriteError(w, oauth2.InvalidClient("unknown client"))
		return
	}

	// authenticate client
	if client.Confidential && !SameHash(client.Secret, req.ClientSecret) {
		_ = oauth2.WriteError(w, oauth2.InvalidClient("unknown client"))
		return
	}

	// parse token
	token, err := hmacsha.Parse(s.config.Secret, req.Token)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	// check access token
	if accessToken, found := s.accessTokens[token.SignatureString()]; found {
		// check owner
		if accessToken.ClientID != req.ClientID {
			_ = oauth2.WriteError(w, oauth2.InvalidClient("wrong client"))
			return
		}

		// revoke token
		s.revokeToken(client, s.accessTokens, token.SignatureString())
	}

	// check refresh token
	if refreshToken, found := s.refreshTokens[token.SignatureString()]; found {
		// check owner
		if refreshToken.ClientID != req.ClientID {
			_ = oauth2.WriteError(w, oauth2.InvalidClient("wrong client"))
			return
		}

		// revoke token
		s.revokeToken(client, s.refreshTokens, token.SignatureString())
	}

	// write header
	w.WriteHeader(http.StatusOK)
}

func (s *Server) introspectionEndpoint(w http.ResponseWriter, r *http.Request) {
	// parse authorization request
	req, err := introspection.ParseRequest(r)
	if err != nil {
		_ = oauth2.WriteError(w, err)
		return
	}

	// check token type hint
	if req.TokenTypeHint != "" && !introspection.KnownTokenType(req.TokenTypeHint) {
		_ = oauth2.WriteError(w, introspection.UnsupportedTokenType(""))
		return
	}

	// get client
	client, found := s.clients[req.ClientID]
	if !found {
		_ = oauth2.WriteError(w, oauth2.InvalidClient("unknown client"))
		return
	}

	// authenticate client
	if client.Confidential && !SameHash(client.Secret, req.ClientSecret) {
		_ = oauth2.WriteError(w, oauth2.InvalidClient("unknown client"))
		return
	}

	// parse token
	token, err := hmacsha.Parse(s.config.Secret, req.Token)
	if err != nil {
		w.WriteHeader(http.StatusOK)
		return
	}

	// prepare response
	res := &introspection.Response{}

	// check access token
	if accessToken, found := s.accessTokens[token.SignatureString()]; found {
		// check owner
		if accessToken.ClientID != req.ClientID {
			_ = oauth2.WriteError(w, oauth2.InvalidClient("wrong client"))
			return
		}

		// set response
		res.Active = true
		res.Scope = accessToken.Scope.String()
		res.ClientID = accessToken.ClientID
		res.Username = accessToken.Username
		res.TokenType = introspection.AccessToken
		res.ExpiresAt = accessToken.ExpiresAt.Unix()
	}

	// check refresh token
	if refreshToken, found := s.refreshTokens[token.SignatureString()]; found {
		// check owner
		if refreshToken.ClientID != req.ClientID {
			_ = oauth2.WriteError(w, oauth2.InvalidClient("wrong client"))
			return
		}

		// set response
		res.Active = true
		res.Scope = refreshToken.Scope.String()
		res.ClientID = refreshToken.ClientID
		res.Username = refreshToken.Username
		res.TokenType = introspection.RefreshToken
		res.ExpiresAt = refreshToken.ExpiresAt.Unix()
	}

	// write response
	_ = introspection.WriteResponse(w, res)
}

func (s *Server) issueTokens(issueRefreshToken bool, scope oauth2.Scope, clientID, username, code string) *oauth2.TokenResponse {
	// generate access token
	accessToken := s.config.MustGenerate()

	// generate refresh token if requested
	var refreshToken *hmacsha.Token
	if issueRefreshToken {
		refreshToken = s.config.MustGenerate()
	}

	// prepare response
	r := bearer.NewTokenResponse(accessToken.String(), int(s.config.AccessTokenLifespan/time.Second))

	// set granted scope
	r.Scope = scope

	// set refresh token if available
	if refreshToken != nil {
		r.RefreshToken = refreshToken.String()
	}

	// save access token
	s.accessTokens[accessToken.SignatureString()] = &Credential{
		ClientID:  clientID,
		Username:  username,
		Signature: accessToken.SignatureString(),
		ExpiresAt: time.Now().Add(s.config.AccessTokenLifespan),
		Scope:     scope,
		Code:      code,
	}

	// save refresh token if available
	if refreshToken != nil {
		s.refreshTokens[refreshToken.SignatureString()] = &Credential{
			ClientID:  clientID,
			Username:  username,
			Signature: refreshToken.SignatureString(),
			ExpiresAt: time.Now().Add(s.config.RefreshTokenLifespan),
			Scope:     scope,
			Code:      code,
		}
	}

	return r
}

func (s *Server) revokeToken(client *Entity, list map[string]*Credential, signature string) {
	// get token
	token, ok := list[signature]
	if !ok {
		return
	}

	// check client id
	if token.ClientID != client.ID {
		return
	}

	// remove token
	delete(list, signature)
}
