package flow

import (
	"net/http"
	"time"

	"github.com/gonfire/oauth2"
	"github.com/gonfire/oauth2/bearer"
)

// AuthorizeResourceAccess will parse the bearer token from the specified request
// and return any error.
func AuthorizeResourceAccess(d Delegate, r *http.Request, requiredScope oauth2.Scope) (AccessToken, error) {
	// parse bearer token
	bt, err := bearer.ParseToken(r)
	if err != nil {
		return nil, err
	}

	// lookup access token
	at, err := d.LookupAccessToken(bt)
	if err == ErrMalformed {
		return nil, bearer.InvalidToken("Malformed access token")
	} else if err == ErrNotFound {
		return nil, bearer.InvalidToken("Unkown token")
	} else if err != nil {
		return nil, err
	}

	// validate expiration
	if at.ExpiresAt().Before(time.Now()) {
		return nil, bearer.InvalidToken("Expired token")
	}

	// validate scope
	if !at.Scope().Includes(requiredScope) {
		return nil, bearer.InsufficientScope(requiredScope.String())
	}

	return at, nil
}
