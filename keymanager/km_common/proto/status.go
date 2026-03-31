// Package keymanager provides common cryptographic utilities and FFI wrappers.
package keymanager

import (
	"fmt"
)

// FFIStatus represents a status returned from the Rust FFI.
type FFIStatus struct {
	Code Status
}

func (e *FFIStatus) Error() string {
	return fmt.Sprintf("FFI status: %s", e.Code.String())
}

// Is allows users to check errors.Is(err, Status_CODE) or errors.Is(err, &FFIStatus{Code: Status_CODE}).
func (e *FFIStatus) Is(target error) bool {
	if t, ok := target.(Status); ok {
		return e.Code == t
	}
	if t, ok := target.(*FFIStatus); ok {
		return e.Code == t.Code
	}
	return false
}

// Status returns the string representation of the Status.
func (e Status) Status() string {
	return e.String()
}

// Error allows Status to be used as a Go error for comparison in errors.Is.
func (e Status) Error() string {
	return e.String()
}

// ToStatus converts a Status to a Go error, or returns nil if it is Success.
func (e Status) ToStatus() error {
	if e == Status_STATUS_SUCCESS {
		return nil
	}
	return &FFIStatus{Code: e}
}
