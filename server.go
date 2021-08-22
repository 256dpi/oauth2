package oauth2

import (
	"net/http"
	"strings"
	"sync"
	"time"
)

// ServerConfig is used to configure a server.
type ServerConfig struct {
	Secret                    []byte
	KeyLength                 int
	AllowedScope              Scope
	AccessTokenLifespan       time.Duration
	RefreshTokenLifespan      time.Duration
	AuthorizationCodeLifespan time.Duration
}

// DefaultServerConfig will return a default configuration.
func DefaultServerConfig(secret []byte, allowed Scope) ServerConfig {
	return ServerConfig{
		Secret:                    secret,
		KeyLength:                 16,
		AllowedScope:              allowed,
		AccessTokenLifespan:       time.Hour,
		RefreshTokenLifespan:      7 * 24 * time.Hour,
		AuthorizationCodeLifespan: 10 * time.Minute,
	}
}

// MustGenerate will generate a new token.
func (c ServerConfig) MustGenerate() *HS256Token {
	return MustGenerateHS256Token(c.Secret, c.KeyLength)
}

// ServerEntity represents a client or resource owner.
type ServerEntity struct {
	Secret       string
	RedirectURI  string
	Confidential bool
}

// ServerCredential represents an access token, refresh token or authorization code.
type ServerCredential struct {
	ClientID    string
	Username    string
	ExpiresAt   time.Time
	Scope       Scope
	RedirectURI string
	Code        string
	Used        bool
}

// Server implements a basic in-memory OAuth2 authentication server intended for
// testing purposes.
type Server struct {
	Config             ServerConfig
	Clients            map[string]*ServerEntity
	Users              map[string]*ServerEntity
	AccessTokens       map[string]*ServerCredential
	RefreshTokens      map[string]*ServerCredential
	AuthorizationCodes map[string]*ServerCredential
	Mutex              sync.Mutex
}

// NewServer creates and returns a new server.
func NewServer(config ServerConfig) *Server {
	return &Server{
		Config:             config,
		Clients:            map[string]*ServerEntity{},
		Users:              map[string]*ServerEntity{},
		AccessTokens:       map[string]*ServerCredential{},
		RefreshTokens:      map[string]*ServerCredential{},
		AuthorizationCodes: map[string]*ServerCredential{},
	}
}

// Authorize will authorize the request and require a valid access token. An
// error has already be written to the client if false is returned.
func (s *Server) Authorize(w http.ResponseWriter, r *http.Request, required Scope) bool {
	// acquire mutex
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	// parse bearer token
	tk, err := ParseBearerToken(r)
	if err != nil {
		_ = WriteBearerError(w, err)
		return false
	}

	// parse token
	token, err := ParseHS256Token(s.Config.Secret, tk)
	if err != nil {
		_ = WriteBearerError(w, InvalidToken("malformed token"))
		return false
	}

	// get token
	accessToken, found := s.AccessTokens[token.SignatureString()]
	if !found {
		_ = WriteBearerError(w, InvalidToken("unknown token"))
		return false
	}

	// validate expiration
	if accessToken.ExpiresAt.Before(time.Now()) {
		_ = WriteBearerError(w, InvalidToken("expired token"))
		return false
	}

	// validate scope
	if !accessToken.Scope.Includes(required) {
		_ = WriteBearerError(w, InsufficientScope(required.String()))
		return false
	}

	return true
}

// ServeHTTP will handle the provided request based on the last path segment
// of the request URL.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// acquire mutex
	s.Mutex.Lock()
	defer s.Mutex.Unlock()

	// get path
	path := r.URL.Path

	// get last path segment
	idx := strings.LastIndexByte(path, '/')
	if idx >= 0 {
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
	req, err := ParseAuthorizationRequest(r)
	if err != nil {
		_ = WriteError(w, err)
		return
	}

	// make sure the response type is known
	if !KnownResponseType(req.ResponseType) {
		_ = WriteError(w, InvalidRequest("unknown response type"))
		return
	}

	// get client
	client, found := s.Clients[req.ClientID]
	if !found {
		_ = WriteError(w, InvalidClient("unknown client"))
		return
	}

	// validate redirect uri
	if client.RedirectURI != req.RedirectURI {
		_ = WriteError(w, InvalidRequest("invalid redirect URI"))
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
	case TokenResponseType:
		s.handleImplicitGrant(w, username, password, req)
	case CodeResponseType:
		s.handleAuthorizationCodeGrantAuthorization(w, username, password, req)
	}
}

func (s *Server) handleImplicitGrant(w http.ResponseWriter, username, password string, rq *AuthorizationRequest) {
	// validate scope
	if !s.Config.AllowedScope.Includes(rq.Scope) {
		_ = WriteError(w, InvalidScope("").SetRedirect(rq.RedirectURI, rq.State, true))
		return
	}

	// validate user credentials
	owner, found := s.Users[username]
	if !found || owner.Secret != password {
		_ = WriteError(w, AccessDenied("").SetRedirect(rq.RedirectURI, rq.State, true))
		return
	}

	// issue tokens
	r := s.issueTokens(false, rq.Scope, rq.ClientID, username, "")

	// redirect token
	r.SetRedirect(rq.RedirectURI, rq.State)

	// write response
	_ = WriteTokenResponse(w, r)
}

func (s *Server) handleAuthorizationCodeGrantAuthorization(w http.ResponseWriter, username, password string, rq *AuthorizationRequest) {
	// validate scope
	if !s.Config.AllowedScope.Includes(rq.Scope) {
		_ = WriteError(w, InvalidScope("").SetRedirect(rq.RedirectURI, rq.State, false))
		return
	}

	// validate user credentials
	owner, found := s.Users[username]
	if !found || owner.Secret != password {
		_ = WriteError(w, AccessDenied("").SetRedirect(rq.RedirectURI, rq.State, false))
		return
	}

	// generate new authorization code
	authorizationCode := s.Config.MustGenerate()

	// prepare response
	r := NewCodeResponse(authorizationCode.String(), rq.RedirectURI, rq.State)

	// save authorization code
	s.AuthorizationCodes[authorizationCode.SignatureString()] = &ServerCredential{
		ClientID:    rq.ClientID,
		Username:    username,
		ExpiresAt:   time.Now().Add(s.Config.AuthorizationCodeLifespan),
		Scope:       rq.Scope,
		RedirectURI: rq.RedirectURI,
	}

	// write response
	_ = WriteCodeResponse(w, r)
}

func (s *Server) tokenEndpoint(w http.ResponseWriter, r *http.Request) {
	// parse token request
	req, err := ParseTokenRequest(r)
	if err != nil {
		_ = WriteError(w, err)
		return
	}

	// make sure the grant type is known
	if !KnownGrantType(req.GrantType) {
		_ = WriteError(w, InvalidRequest("unknown grant type"))
		return
	}

	// find client
	client, found := s.Clients[req.ClientID]
	if !found {
		_ = WriteError(w, InvalidClient("unknown client"))
		return
	}

	// authenticate client
	if client.Confidential && client.Secret != req.ClientSecret {
		_ = WriteError(w, InvalidClient("unknown client"))
		return
	}

	// handle grant type
	switch req.GrantType {
	case PasswordGrantType:
		s.handleResourceOwnerPasswordCredentialsGrant(w, req)
	case ClientCredentialsGrantType:
		s.handleClientCredentialsGrant(w, req)
	case AuthorizationCodeGrantType:
		s.handleAuthorizationCodeGrant(w, req)
	case RefreshTokenGrantType:
		s.handleRefreshTokenGrant(w, req)
	}
}

func (s *Server) handleResourceOwnerPasswordCredentialsGrant(w http.ResponseWriter, rq *TokenRequest) {
	// authenticate resource owner
	owner, found := s.Users[rq.Username]
	if !found || owner.Secret != rq.Password {
		_ = WriteError(w, AccessDenied(""))
		return
	}

	// check scope
	if !s.Config.AllowedScope.Includes(rq.Scope) {
		_ = WriteError(w, InvalidScope(""))
		return
	}

	// issue tokens
	r := s.issueTokens(true, rq.Scope, rq.ClientID, rq.Username, "")

	// write response
	_ = WriteTokenResponse(w, r)
}

func (s *Server) handleClientCredentialsGrant(w http.ResponseWriter, rq *TokenRequest) {
	// check client confidentiality
	if !s.Clients[rq.ClientID].Confidential {
		_ = WriteError(w, InvalidClient("unknown client"))
		return
	}

	// check scope
	if !s.Config.AllowedScope.Includes(rq.Scope) {
		_ = WriteError(w, InvalidScope(""))
		return
	}

	// save tokens
	r := s.issueTokens(true, rq.Scope, rq.ClientID, "", "")

	// write response
	_ = WriteTokenResponse(w, r)
}

func (s *Server) handleAuthorizationCodeGrant(w http.ResponseWriter, rq *TokenRequest) {
	// parse authorization code
	authorizationCode, err := ParseHS256Token(s.Config.Secret, rq.Code)
	if err != nil {
		_ = WriteError(w, InvalidRequest(err.Error()))
		return
	}

	// get stored authorization code by signature
	storedAuthorizationCode, found := s.AuthorizationCodes[authorizationCode.SignatureString()]
	if !found {
		_ = WriteError(w, InvalidGrant("unknown authorization code"))
		return
	}

	// check if used
	if storedAuthorizationCode.Used {
		// revoke all access tokens
		for key, token := range s.AccessTokens {
			if token.Code == authorizationCode.SignatureString() {
				delete(s.AccessTokens, key)
			}
		}

		// revoke all refresh tokens
		for key, token := range s.RefreshTokens {
			if token.Code == authorizationCode.SignatureString() {
				delete(s.RefreshTokens, key)
			}
		}

		_ = WriteError(w, InvalidGrant("unknown authorization code"))
		return
	}

	// validate expiration
	if storedAuthorizationCode.ExpiresAt.Before(time.Now()) {
		_ = WriteError(w, InvalidGrant("expired authorization code"))
		return
	}

	// validate ownership
	if storedAuthorizationCode.ClientID != rq.ClientID {
		_ = WriteError(w, InvalidGrant("invalid authorization code ownership"))
		return
	}

	// validate redirect uri
	if storedAuthorizationCode.RedirectURI != rq.RedirectURI {
		_ = WriteError(w, InvalidGrant("changed redirect uri"))
		return
	}

	// issue tokens
	r := s.issueTokens(true, storedAuthorizationCode.Scope, rq.ClientID, storedAuthorizationCode.Username, authorizationCode.SignatureString())

	// mark authorization code
	storedAuthorizationCode.Used = true

	// write response
	_ = WriteTokenResponse(w, r)
}

func (s *Server) handleRefreshTokenGrant(w http.ResponseWriter, rq *TokenRequest) {
	// parse refresh token
	refreshToken, err := ParseHS256Token(s.Config.Secret, rq.RefreshToken)
	if err != nil {
		_ = WriteError(w, InvalidRequest(err.Error()))
		return
	}

	// get stored refresh token by signature
	storedRefreshToken, found := s.RefreshTokens[refreshToken.SignatureString()]
	if !found {
		_ = WriteError(w, InvalidGrant("unknown refresh token"))
		return
	}

	// validate expiration
	if storedRefreshToken.ExpiresAt.Before(time.Now()) {
		_ = WriteError(w, InvalidGrant("expired refresh token"))
		return
	}

	// validate ownership
	if storedRefreshToken.ClientID != rq.ClientID {
		_ = WriteError(w, InvalidGrant("invalid refresh token ownership"))
		return
	}

	// inherit scope from stored refresh token
	if rq.Scope.Empty() {
		rq.Scope = storedRefreshToken.Scope
	}

	// validate scope - a missing scope is always included
	if !storedRefreshToken.Scope.Includes(rq.Scope) {
		_ = WriteError(w, InvalidScope("scope exceeds the originally granted scope"))
		return
	}

	// issue tokens
	r := s.issueTokens(true, rq.Scope, rq.ClientID, storedRefreshToken.Username, "")

	// delete used refresh token
	delete(s.RefreshTokens, refreshToken.SignatureString())

	// write response
	_ = WriteTokenResponse(w, r)
}

func (s *Server) revocationEndpoint(w http.ResponseWriter, r *http.Request) {
	// parse authorization request
	req, err := ParseRevocationRequest(r)
	if err != nil {
		_ = WriteError(w, err)
		return
	}

	// check token type hint
	if req.TokenTypeHint != "" && !KnownTokenType(req.TokenTypeHint) {
		_ = WriteError(w, UnsupportedTokenType(""))
		return
	}

	// get client
	client, found := s.Clients[req.ClientID]
	if !found {
		_ = WriteError(w, InvalidClient("unknown client"))
		return
	}

	// authenticate client
	if client.Confidential && client.Secret != req.ClientSecret {
		_ = WriteError(w, InvalidClient("unknown client"))
		return
	}

	// parse token
	token, err := ParseHS256Token(s.Config.Secret, req.Token)
	if err != nil {
		_ = WriteError(w, InvalidRequest(err.Error()))
		return
	}

	// check access token
	if accessToken, found := s.AccessTokens[token.SignatureString()]; found {
		// check owner
		if accessToken.ClientID != req.ClientID {
			_ = WriteError(w, InvalidClient("wrong client"))
			return
		}

		// revoke token
		s.revokeToken(req.ClientID, s.AccessTokens, token.SignatureString())
	}

	// check refresh token
	if refreshToken, found := s.RefreshTokens[token.SignatureString()]; found {
		// check owner
		if refreshToken.ClientID != req.ClientID {
			_ = WriteError(w, InvalidClient("wrong client"))
			return
		}

		// revoke token
		s.revokeToken(req.ClientID, s.RefreshTokens, token.SignatureString())
	}

	// write header
	w.WriteHeader(http.StatusOK)
}

func (s *Server) introspectionEndpoint(w http.ResponseWriter, r *http.Request) {
	// parse authorization request
	req, err := ParseIntrospectionRequest(r)
	if err != nil {
		_ = WriteError(w, err)
		return
	}

	// check token type hint
	if req.TokenTypeHint != "" && !KnownTokenType(req.TokenTypeHint) {
		_ = WriteError(w, UnsupportedTokenType(""))
		return
	}

	// get client
	client, found := s.Clients[req.ClientID]
	if !found {
		_ = WriteError(w, InvalidClient("unknown client"))
		return
	}

	// authenticate client
	if client.Confidential && client.Secret != req.ClientSecret {
		_ = WriteError(w, InvalidClient("unknown client"))
		return
	}

	// parse token
	token, err := ParseHS256Token(s.Config.Secret, req.Token)
	if err != nil {
		_ = WriteError(w, InvalidRequest(err.Error()))
		return
	}

	// prepare response
	res := &IntrospectionResponse{}

	// check access token
	if accessToken, found := s.AccessTokens[token.SignatureString()]; found {
		// check owner
		if accessToken.ClientID != req.ClientID {
			_ = WriteError(w, InvalidClient("wrong client"))
			return
		}

		// set response
		res.Active = true
		res.Scope = accessToken.Scope.String()
		res.ClientID = accessToken.ClientID
		res.Username = accessToken.Username
		res.TokenType = AccessToken
		res.ExpiresAt = accessToken.ExpiresAt.Unix()
	}

	// check refresh token
	if refreshToken, found := s.RefreshTokens[token.SignatureString()]; found {
		// check owner
		if refreshToken.ClientID != req.ClientID {
			_ = WriteError(w, InvalidClient("wrong client"))
			return
		}

		// set response
		res.Active = true
		res.Scope = refreshToken.Scope.String()
		res.ClientID = refreshToken.ClientID
		res.Username = refreshToken.Username
		res.TokenType = RefreshToken
		res.ExpiresAt = refreshToken.ExpiresAt.Unix()
	}

	// write response
	_ = WriteIntrospectionResponse(w, res)
}

func (s *Server) issueTokens(issueRefreshToken bool, scope Scope, clientID, username, code string) *TokenResponse {
	// generate access token
	accessToken := s.Config.MustGenerate()

	// generate refresh token if requested
	var refreshToken *HS256Token
	if issueRefreshToken {
		refreshToken = s.Config.MustGenerate()
	}

	// prepare response
	r := NewBearerTokenResponse(accessToken.String(), int(s.Config.AccessTokenLifespan/time.Second))

	// set granted scope
	r.Scope = scope

	// set refresh token if available
	if refreshToken != nil {
		r.RefreshToken = refreshToken.String()
	}

	// save access token
	s.AccessTokens[accessToken.SignatureString()] = &ServerCredential{
		ClientID:  clientID,
		Username:  username,
		ExpiresAt: time.Now().Add(s.Config.AccessTokenLifespan),
		Scope:     scope,
		Code:      code,
	}

	// save refresh token if available
	if refreshToken != nil {
		s.RefreshTokens[refreshToken.SignatureString()] = &ServerCredential{
			ClientID:  clientID,
			Username:  username,
			ExpiresAt: time.Now().Add(s.Config.RefreshTokenLifespan),
			Scope:     scope,
			Code:      code,
		}
	}

	return r
}

func (s *Server) revokeToken(clientID string, list map[string]*ServerCredential, signature string) {
	// get token
	token, ok := list[signature]
	if !ok {
		return
	}

	// check client id
	if token.ClientID != clientID {
		return
	}

	// remove token
	delete(list, signature)
}
