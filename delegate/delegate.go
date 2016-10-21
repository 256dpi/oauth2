package delegate

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

type Delegate interface {
	LookupClient(string) (Client, error)
	LookupResourceOwner(string) (ResourceOwner, error)

	GrantScope(Client, ResourceOwner, oauth2.Scope) (oauth2.Scope, error)
	IssueAccessToken(Client, ResourceOwner, oauth2.Scope) (string, int, error)
}

type AuthorizationDelegate interface {
	Delegate

	ParseConsent(r *oauth2.AuthorizationRequest) (string, string, oauth2.Scope, error)
}

type AuthorizationCodeDelegate interface {
	AuthorizationDelegate

	LookupAuthorizationCode(string) (AuthorizationCode, error)
	IssueAuthorizationCode(Client, ResourceOwner, oauth2.Scope, string) (string, error)
	RemoveAuthorizationCode(string) error
}

type RefreshTokenDelegate interface {
	Delegate

	LookupRefreshToken(string) (RefreshToken, error)
	IssueRefreshToken(Client, ResourceOwner, oauth2.Scope) (string, error)
	RemoveRefreshToken(string) error
}

type Client interface {
	ID() string
	Confidential() bool
	ValidSecret(string) bool
	ValidRedirectURI(string) bool
}

type ResourceOwner interface {
	ID() string
	Username() string
	ValidSecret(string) bool
}

type AuthorizationCode interface {
	ClientID() string
	ResourceOwnerID() string
	ExpiresAt() time.Time
	Scope() oauth2.Scope
	RedirectURI() string
}

type RefreshToken interface {
	ClientID() string
	ResourceOwnerID() string
	ExpiresAt() time.Time
	Scope() oauth2.Scope
}
