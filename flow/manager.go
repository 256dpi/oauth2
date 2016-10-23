package flow

import (
	"errors"
	"net/http"

	"github.com/gonfire/oauth2"
)

type Flow int

const (
	_ Flow = iota
	PasswordFlow
	ClientCredentialsFlow
	ImplicitFlow
	AuthorizationCodeFlow
	RefreshTokenFlow
)

// ToFlow will return the corresponding flow for a known grant or response type.
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

var ErrUnapproved = errors.New("unapproved")

type ManagerDelegate interface {
	Delegate

	ValidateFlow(Client, Flow) error
}

type ErrorHandler func(error)

func ManagedAuthorizationEndpoint(d ManagerDelegate, eh ErrorHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// process authorization request
		ar, c, err := ProcessAuthorizationRequest(d, r)
		if err != nil {
			ForwardError(eh, err.Cause())
			HandleError(w, err)
			return
		}

		// show info notice on a GET request
		if r.Method == "GET" {
			w.Write([]byte("This authentication server does not provide an authorization form.\n" +
				"Please submit the resource owners username and password in the request body."))
			return
		}

		// approve flow
		approveErr := d.ValidateFlow(c, ToFlow(ar.ResponseType))
		if approveErr == ErrUnapproved {
			oauth2.WriteError(w, oauth2.UnauthorizedClient(ar.State, "Unpermitted response type"))
			return
		} else if approveErr != nil {
			ForwardError(eh, approveErr)
			oauth2.WriteError(w, oauth2.ServerError(ar.State, "Failed to approve flow"))
			return
		}

		// triage based on response type
		switch ar.ResponseType {
		case oauth2.TokenResponseType:
			// authorize implicit grant
			res, err := AuthorizeImplicitGrant(d, c, ar)
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
			res, err := HandleAuthorizationCodeGrantAuthorization(acd, c, ar)
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
		approveErr := d.ValidateFlow(c, ToFlow(tr.GrantType))
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

func ForwardError(eh ErrorHandler, err error) {
	if eh != nil && err != nil {
		eh(err)
	}
}
