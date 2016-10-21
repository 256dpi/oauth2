package server

import (
	"net/http"

	"github.com/gonfire/oauth2"
	"github.com/gonfire/oauth2/delegate"
)

func authorizationEndpoint(d *Delegate) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// process authorization request
		ar, c, err := delegate.ProcessAuthorizationRequest(d, r)
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
			res, err := delegate.AuthorizeImplicitGrant(d, c, ar)
			if err != nil {
				oauth2.RedirectError(w, ar.RedirectURI, true, err)
				return
			}

			// redirect response
			oauth2.RedirectTokenResponse(w, ar.RedirectURI, res)
		case oauth2.CodeResponseType:
			// authorize authorization code grant
			res, err := delegate.AuthorizeAuthorizationCodeGrant(d, c, ar)
			if err != nil {
				oauth2.RedirectError(w, ar.RedirectURI, false, err)
				return
			}

			// redirect response
			oauth2.RedirectCodeResponse(w, ar.RedirectURI, res)
		}
	}
}

func tokenEndpoint(d *Delegate) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// process token request
		tr, c, err := delegate.ProcessTokenRequest(d, r)
		if err != nil {
			oauth2.WriteError(w, err)
			return
		}

		switch tr.GrantType {
		case oauth2.PasswordGrantType:
			// handle resource owner password credentials grant
			res, err := delegate.HandlePasswordGrant(d, c, tr)
			if err != nil {
				oauth2.WriteError(w, err)
				return
			}

			// write response
			oauth2.WriteTokenResponse(w, res)
		case oauth2.ClientCredentialsGrantType:
			// handle client credentials grant
			res, err := delegate.HandleClientCredentialsGrant(d, c, tr)
			if err != nil {
				oauth2.WriteError(w, err)
				return
			}

			// write response
			oauth2.WriteTokenResponse(w, res)
		case oauth2.AuthorizationCodeGrantType:
			// handle client credentials grant
			res, err := delegate.HandleAuthorizationCodeGrant(d, c, tr)
			if err != nil {
				oauth2.WriteError(w, err)
				return
			}

			// write response
			oauth2.WriteTokenResponse(w, res)
		case oauth2.RefreshTokenGrantType:
			// handle refresh token grant
			res, err := delegate.HandleRefreshTokenGrant(d, c, tr)
			if err != nil {
				oauth2.WriteError(w, err)
				return
			}

			// write response
			oauth2.WriteTokenResponse(w, res)
		}
	}
}
