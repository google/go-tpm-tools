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

// ToError converts an Error to a Go error, or returns nil if it is Success.
func (e Error) ToError() error {
	if e == Error_ERROR_SUCCESS {
		return nil
	}
	return &FFIError{Code: e}
}
