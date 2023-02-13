package decrypt

import (
	"errors"
)

var (

	// ErrDecrypt is returned when there is an error decrypting something.
	ErrDecrypt = errors.New("decryption failed")
)

// Error contains the Cause and RootCause of an error.
type Error struct {

	// Cause is the package error that defines the Error and is wrapped with whatever information
	// may be useful within the scope of its construction.
	Cause error

	// RootCause is included if the error was triggered by a different package.
	RootCause error
}

// Error returns the string for an error.
func (e *Error) Error() string {
	if e.RootCause == nil {
		return e.Cause.Error()
	}
	return e.Cause.Error() + ": " + e.RootCause.Error()
}

// Unwrap returns the Error's cause.
func (e *Error) Unwrap() error {
	return e.Cause
}
