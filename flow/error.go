package flow

import (
	"github.com/gonfire/oauth2"
	"github.com/gonfire/oauth2/bearer"
	"net/http"
)

// Error is returned by all functions in this package to mainly retain the
// causing error (e.g. a failed database lookup by a delegate) and the to be
// written protocol error (e.g. OAuth2 server error). Additionally it also
// abstracts the several error writing facilities by the underlying packages.
//
// Note: Error does not implement the error interface by design to reduce
// potential wrong error responses caused by not properly handling the errors.
type Error interface {
	Cause() error
}

// OAuth2Error represents an error from the oauth2 package.
type OAuth2Error struct {
	Source      error
	Error       error
	RedirectURI string
	UseFragment bool
}

// Cause implements the Error interface.
func (e *OAuth2Error) Cause() error {
	return e.Source
}

// BearerError represents an error from the bearer package.
type BearerError struct {
	Source error
	Error  error
}

// Cause implements the Error interface.
func (e *BearerError) Cause() error {
	return e.Source
}

// HandleError handles the specified error.
func HandleError(w http.ResponseWriter, err Error) {
	// handle oauth2 package errors
	if or, ok := err.(*OAuth2Error); ok {
		if or.RedirectURI != "" {
			oauth2.RedirectError(w, or.RedirectURI, or.UseFragment, or.Error)
			return
		}

		oauth2.WriteError(w, or.Error)
	}

	// handle bearer package errors
	if ar, ok := err.(*BearerError); ok {
		bearer.WriteError(w, ar.Error)
		return
	}
}
