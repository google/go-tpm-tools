package launcher

import "fmt"

// RetryableError means launcher should reboot the VM to retry.
type RetryableError struct {
	Err error
}

// WorkloadError represents the result of an workload/task that is non-zero.
type WorkloadError struct {
	ReturnCode uint32
}

func (e *RetryableError) Error() string {
	return fmt.Sprintf("failed with retryable error: %v", e.Err.Error())
}

func (e *WorkloadError) Error() string {
	return "workload finished with a non-zero return code"
}

// TPMOpenError represents a failure to open the TPM device.
type TPMOpenError struct {
	Err error
}

func (e *TPMOpenError) Error() string {
	return fmt.Sprintf("failed to open TPM device: %v", e.Err)
}

func (e *TPMOpenError) Unwrap() error {
	return e.Err
}

// TPMInitError represents a failure to initialize/validate the TPM.
type TPMInitError struct {
	Err error
}

func (e *TPMInitError) Error() string {
	return fmt.Sprintf("failed to initialize TPM: %v", e.Err)
}

func (e *TPMInitError) Unwrap() error {
	return e.Err
}
