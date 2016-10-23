package flow

import (
	"errors"
	"time"

	"github.com/gonfire/oauth2"
)

// ErrNotFound can be returned by the delegate to indicate that the requested
// client, resource owner, authorization code or refresh token has not been found,
var ErrNotFound = errors.New("not found")

// ErrMalformed can be returned by the delegate to indicate that the provided
// authorization code or refresh token is malformed.
var ErrMalformed = errors.New("malformed")

// ErrRejected can be returned by the delegate to indicate that the provided
// scope has been rejected and the current request should be denied.
var ErrRejected = errors.New("rejected")

// The Delegate interface defines the basic set of methods needed to implement
// a delegate that can be used in conjunction with the functions in this package
// to implement an OAuth2 compatible authentication server.
type Delegate interface {
	// LookupClient should look for a client with the specified id. If the client
	// has not been found the method should return ErrNotFound to indicate the
	// absence. Any other returned errors are treated as internal server errors.
	LookupClient(string) (Client, error)

	// LookupResourceOwner should look for a resource owner with the specified id.
	// If the resource owner has not been found the method should return
	// ErrNotFound to indicate the absence. Any other returned errors are treated
	// as internal server errors.
	LookupResourceOwner(string) (ResourceOwner, error)

	// ParseConsent should parse the specified request and return the id and
	// secret of the to be authorized resource owner together with the requested
	// scope. Any returned error is treated as an internal server error.
	ParseConsent(r *oauth2.AuthorizationRequest) (string, string, oauth2.Scope, error)

	GrantScope(Client, ResourceOwner, oauth2.Scope) (oauth2.Scope, error)

	// IssueAccessToken should issue an access token for the specified client and
	// return the key and expiry in seconds or any potential errors. The access
	// token is issued on the behalf of the specified resource owner with the
	// specified scope that has been granted. Any returned error is treated as
	// an internal server error.
	//
	// Note: The resource owner is not set during the client credentials grant.
	IssueAccessToken(Client, ResourceOwner, oauth2.Scope) (string, int, error)
}

// The AuthorizationCodeDelegate defines an additional set of methods needed to
// implement a delegate that can be used in conjunction with the authorization
// code grant related functions in this package.
type AuthorizationCodeDelegate interface {
	Delegate

	// LookupAuthorizationCode should look for an authorization code with the
	// specified key. If the authorization code has not been found the method
	// should return ErrNotFound to indicate the absence. Any other returned
	// errors are treated as internal server errors.
	LookupAuthorizationCode(string) (AuthorizationCode, error)

	// IssueAuthorizationCode should issue an authorization code for the specified
	// client and return the code or any potential errors. The authorization
	// code is issued on the behalf of the specified resource owner with the
	// specified scope that has been granted. Any returned error is treated as
	// an internal server error.
	IssueAuthorizationCode(Client, ResourceOwner, oauth2.Scope, string) (string, error)

	// RemoveAuthorizationCode should remove the specified authorization code.
	RemoveAuthorizationCode(string) error
}

// The RefreshTokenDelegate defines an additional set of methods needed to
// implement a delegate that can be used in conjunction with the refresh token
// grant related functions in this package.
type RefreshTokenDelegate interface {
	Delegate

	// LookupRefreshToken should look for a refresh token with the specified key.
	// If the authorization code has not been found the method should return
	// ErrNotFound to indicate the absence. Any other returned errors are treated
	// as internal server errors.
	LookupRefreshToken(string) (RefreshToken, error)

	// IssueRefreshToken should issue a refresh token for the specified client
	// and return the key or any potential errors. The refresh token is issued
	// on the behalf of the specified resource owner with the specified scope
	// that has been granted. Any returned error is treated as an internal
	// server error.
	IssueRefreshToken(Client, ResourceOwner, oauth2.Scope) (string, error)

	// RemoveRefreshToken should remove the specified refresh token.
	RemoveRefreshToken(string) error
}

// The Client interface defines the abstracts model of a client that requests
// access to resource on behalf of a resource owner.
type Client interface {
	// ID should return the id of the client.
	ID() string

	// Confidential should return true if the client is marked as being
	// confidential, i.e. will authenticate itself using a secret.
	Confidential() bool

	// ValidSecret should return true if the specified secret matches the
	// stored secret.
	ValidSecret(string) bool

	// ValidRedirectURI should return true if the specified redirect uri
	// is valid, i.e. has been already recorded by the client.
	ValidRedirectURI(string) bool
}

// The ResourceOwner interface defines the abstract model of a resource owner
// that authorizes a client to access his resources.
type ResourceOwner interface {
	// ID should return the id of the resource owner.
	ID() string

	// ValidSecret should return true if the specified secret matches the
	// stored secret.
	ValidSecret(string) bool
}

// The AuthorizationCode interface defines the abstract model of an authorization
// code that is used to obtain an access token in a second step.
type AuthorizationCode interface {
	// ClientID should return the id of the client that this authorization code
	// is associated with.
	ClientID() string

	// ResourceOwnerID should return the id of the resource owner that this
	// authorization code is associated with.
	ResourceOwnerID() string

	// ExpiresAt should return the date on which this authorization code expires.
	ExpiresAt() time.Time

	// Scope should return the scope that has been originally granted.
	Scope() oauth2.Scope

	// RedirectURI should return the redirect uri that has been used to obtain
	// the authorization code.
	RedirectURI() string
}

// The RefreshToken interface defines the abstract model of a refresh token
// that is used to obtain a new access and eventual refresh token.
type RefreshToken interface {
	// ClientID should return the id of the client that this refresh token is
	// associated with.
	ClientID() string

	// ResourceOwnerID should return the id of the resource owner that this
	// refresh token is associated with.
	ResourceOwnerID() string

	// ExpiresAt should return the date on which this refresh token expires.
	ExpiresAt() time.Time

	// Scope should return the scope that has been originally granted.
	Scope() oauth2.Scope
}
