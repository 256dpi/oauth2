package flow

// Error is returned by all functions in this package to retain the causing error
// (e.g. a failed database lookup by a delegate) and the to be written protocol
// error (e.g. OAuth2 server error).
//
// Note: The Error does not implement error by design to reduce potential wrong
// error responses caused by not properly unwrapping the error.
type Error struct {
	// Cause is the error returned by the delegate.
	Cause error

	// Error is the protocol error that should be written or redirected.
	Error error
}

// WrapError constructs an Error from two errors.
func WrapError(cause, err error) *Error {
	return &Error{cause, err}
}
