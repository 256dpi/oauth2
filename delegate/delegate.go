package delegate

import (
	"errors"
	"time"

	"github.com/gonfire/oauth2"
)

var ErrNotFound = errors.New("not found")
var ErrMalformed = errors.New("malformed")
var ErrRejected = errors.New("rejected") // TODO: Rename to refused?

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
