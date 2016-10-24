package flow

import (
	"errors"
	"net/http"

	"github.com/gonfire/oauth2"
)

// Flow represents a known OAuth2 flow.
type Flow int

// All known OAuth2 flows.
const (
	_ Flow = iota
	PasswordFlow
	ClientCredentialsFlow
	ImplicitFlow
	AuthorizationCodeFlow
	RefreshTokenFlow
)

// ToFlow will return the corresponding flow for a known grant or response type.
//
// Note: ToFlow will panic if the provide grant or response type is not known.
func ToFlow(str string) Flow {
	switch str {
	case oauth2.PasswordGrantType:
		return PasswordFlow
	case oauth2.ClientCredentialsGrantType:
		return ClientCredentialsFlow
	case oauth2.AuthorizationCodeGrantType:
		return AuthorizationCodeFlow
	case oauth2.RefreshTokenGrantType:
		return RefreshTokenFlow
	case oauth2.TokenResponseType:
		return ImplicitFlow
	case oauth2.CodeResponseType:
		return AuthorizationCodeFlow
	}

	panic("unknown grant or response type")
}

// ErrUnapproved can be returned by the delegate to indicate that the requested
// flow has not been approved.
var ErrUnapproved = errors.New("unapproved")

// The ManagerDelegate defines an additional set of methods needed to
// implement a delegate that can be used in conjunction with the managed token
// and authorization endpoint functions.
type ManagerDelegate interface {
	Delegate

	// ValidateFlow should validate the requested flow and return nil if it is
	// allowed. If the flow in general or for the specified client is not allowed
	// it should return ErrUnapproved. Any other returned error is treated as an
	// internal server error.
	//
	// Note: Only allow flows that are implemented by the delegate. Using a non
	// implemented flow will result in a runtime panic.
	ValidateFlow(Flow, Client) error

	// ObtainConsent should parse the specified request and if all data is
	// available return a consent with the parsed data. If data is missing the
	// delegate should completely handle the request (to inform the user) and
	// return nil.
	ObtainConsent(w http.ResponseWriter, r *oauth2.AuthorizationRequest) *Consent
}

// The ErrorHandler receives unexpected errors returned by delegates.
type ErrorHandler func(error)

// ManagedAuthorizationEndpoint constructs a request handler that manages the
// authorization endpoint using the specified delegate.
//
// It will parse all requests and perform basic validations recommended by the
// OAuth2 spec. When the specified flow has been approved using ValidateFlow it
// will call ObtainConsent to inquire the resources owners consent. If the
// the resource owner has given his consent the flows are handled.
func ManagedAuthorizationEndpoint(d ManagerDelegate, eh ErrorHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// process authorization request
		ar, c, err := ProcessAuthorizationRequest(d, r)
		if err != nil {
			ForwardError(eh, err.Cause())
			HandleError(w, err)
			return
		}

		// approve flow
		approveErr := d.ValidateFlow(ToFlow(ar.ResponseType), c)
		if approveErr == ErrUnapproved {
			oauth2.WriteError(w, oauth2.UnauthorizedClient(ar.State, "Unpermitted response type"))
			return
		} else if approveErr != nil {
			ForwardError(eh, approveErr)
			oauth2.WriteError(w, oauth2.ServerError(ar.State, "Failed to approve flow"))
			return
		}

		// obtain consent and return when missing
		consent := d.ObtainConsent(w, ar)
		if consent == nil {
			return
		}

		// triage based on response type
		switch ar.ResponseType {
		case oauth2.TokenResponseType:
			// authorize implicit grant
			res, err := HandleImplicitGrant(d, c, consent, ar)
			if err != nil {
				ForwardError(eh, err.Cause())
				HandleError(w, err)
				return
			}

			// redirect response
			oauth2.RedirectTokenResponse(w, ar.RedirectURI, res)
		case oauth2.CodeResponseType:
			// force authorization code delegate
			acd := d.(AuthorizationCodeDelegate)

			// authorize authorization code grant
			res, err := HandleAuthorizationCodeGrantAuthorization(acd, c, consent, ar)
			if err != nil {
				ForwardError(eh, err.Cause())
				HandleError(w, err)
				return
			}

			// redirect response
			oauth2.RedirectCodeResponse(w, ar.RedirectURI, res)
		}
	}
}

// ManagedTokenEndpoint constructs a request handler that manages the token
// endpoint using the specified delegate.
func ManagedTokenEndpoint(d ManagerDelegate, eh ErrorHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// process token request
		tr, c, err := ProcessTokenRequest(d, r)
		if err != nil {
			ForwardError(eh, err.Cause())
			HandleError(w, err)
			return
		}

		// approve flow
		approveErr := d.ValidateFlow(ToFlow(tr.GrantType), c)
		if approveErr == ErrUnapproved {
			oauth2.WriteError(w, oauth2.UnauthorizedClient(oauth2.NoState, "Unpermitted grant type"))
			return
		} else if approveErr != nil {
			ForwardError(eh, approveErr)
			oauth2.WriteError(w, oauth2.ServerError(oauth2.NoState, "Failed to approve flow"))
			return
		}

		// prepare response
		var res *oauth2.TokenResponse

		// handle grant
		switch tr.GrantType {
		case oauth2.PasswordGrantType:
			res, err = HandlePasswordGrant(d, c, tr)
		case oauth2.ClientCredentialsGrantType:
			res, err = HandleClientCredentialsGrant(d, c, tr)
		case oauth2.AuthorizationCodeGrantType:
			// force authorization code delegate
			acd := d.(AuthorizationCodeDelegate)

			res, err = HandleAuthorizationCodeGrant(acd, c, tr)
		case oauth2.RefreshTokenGrantType:
			// force refresh token delegate
			rtd := d.(RefreshTokenDelegate)

			res, err = HandleRefreshTokenGrant(rtd, c, tr)
		}

		// check error
		if err != nil {
			ForwardError(eh, err.Cause())
			HandleError(w, err)
			return
		}

		// write response
		oauth2.WriteTokenResponse(w, res)
	}
}

// ForwardError will call the specified error handler with the error if both
// are available.
func ForwardError(eh ErrorHandler, err error) {
	if eh != nil && err != nil {
		eh(err)
	}
}
