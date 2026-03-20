// Package keymanager provides common cryptographic utilities and FFI wrappers.
package keymanager

import (
	"fmt"
)

// FFIError represents an error returned from the Rust FFI.
type FFIError struct {
	Code Error
}

func (e *FFIError) Error() string {
	return fmt.Sprintf("FFI error: %s", e.Code.String())
}

// Is allows users to check errors.Is(err, Error_CODE) or errors.Is(err, &FFIError{Code: Error_CODE}).
func (e *FFIError) Is(target error) bool {
	if t, ok := target.(Error); ok {
		return e.Code == t
	}
	if t, ok := target.(*FFIError); ok {
		return e.Code == t.Code
	}
	return false
}

// Error allows Error to be used as a Go error.
func (e Error) Error() string {
	return e.String()
}

// ToError converts an Error to a Go error, or returns nil if it is Success.
func (e Error) ToError() error {
	if e == Error_ERROR_SUCCESS {
		return nil
	}
	return &FFIError{Code: e}
}
