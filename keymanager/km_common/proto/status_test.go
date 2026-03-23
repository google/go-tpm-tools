package keymanager

import (
	"errors"
	"testing"
)

func TestFFIStatus(t *testing.T) {
	err := Status_STATUS_INTERNAL_ERROR.ToStatus()
	if err == nil {
		t.Fatalf("ToStatus() = nil, want error")
	}

	// Test simplified comparison
	if !errors.Is(err, Status_STATUS_INTERNAL_ERROR) {
		t.Errorf("errors.Is(err, Status_STATUS_INTERNAL_ERROR) = false, want true")
	}
	if errors.Is(err, Status_STATUS_INVALID_ARGUMENT) {
		t.Errorf("errors.Is(err, Status_STATUS_INVALID_ARGUMENT) = true, want false")
	}

	// Test with FFIStatus pointer
	if !errors.Is(err, &FFIStatus{Code: Status_STATUS_INTERNAL_ERROR}) {
		t.Errorf("errors.Is(err, &FFIStatus{Code: Status_STATUS_INTERNAL_ERROR}) = false, want true")
	}
	if errors.Is(err, &FFIStatus{Code: Status_STATUS_INVALID_ARGUMENT}) {
		t.Errorf("errors.Is(err, &FFIStatus{Code: Status_STATUS_INVALID_ARGUMENT}) = true, want false")
	}

	// Test other error type
	if errors.Is(err, errors.New("other error")) {
		t.Errorf("errors.Is(err, errors.New(\"other error\")) = true, want false")
	}
}

func TestFFIStatusSuccess(t *testing.T) {
	if err := Status_STATUS_SUCCESS.ToStatus(); err != nil {
		t.Errorf("Status_STATUS_SUCCESS.ToStatus() = %v, want nil", err)
	}
}

func TestStatusMethod(t *testing.T) {
	val := Status_STATUS_INTERNAL_ERROR
	if val.Status() != "STATUS_INTERNAL_ERROR" {
		t.Errorf("Status_STATUS_INTERNAL_ERROR.Status() = %q, want \"STATUS_INTERNAL_ERROR\"", val.Status())
	}
}
