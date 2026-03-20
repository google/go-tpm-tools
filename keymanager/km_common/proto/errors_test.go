package keymanager

import (
	"errors"
	"testing"
)

func TestFFIErrorIs(t *testing.T) {
	err := Error_ERROR_INTERNAL.ToError()

	// Check against Error type
	if !errors.Is(err, Error_ERROR_INTERNAL) {
		t.Errorf("errors.Is(err, Error_ERROR_INTERNAL) = false, want true")
	}
	if errors.Is(err, Error_ERROR_INVALID_ARGUMENT) {
		t.Errorf("errors.Is(err, Error_ERROR_INVALID_ARGUMENT) = true, want false")
	}

	// Check against FFIError type
	if !errors.Is(err, &FFIError{Code: Error_ERROR_INTERNAL}) {
		t.Errorf("errors.Is(err, &FFIError{Code: Error_ERROR_INTERNAL}) = false, want true")
	}
	if errors.Is(err, &FFIError{Code: Error_ERROR_INVALID_ARGUMENT}) {
		t.Errorf("errors.Is(err, &FFIError{Code: Error_ERROR_INVALID_ARGUMENT}) = true, want false")
	}

	// Check against unrelated error
	if errors.Is(err, errors.New("some other error")) {
		t.Errorf("errors.Is(err, errors.New(\"some other error\")) = true, want false")
	}
}

func TestErrorAsError(t *testing.T) {
	var err error = Error_ERROR_INTERNAL
	if err.Error() != "ERROR_INTERNAL" {
		t.Errorf("Error_ERROR_INTERNAL.Error() = %q, want \"ERROR_INTERNAL\"", err.Error())
	}
}
