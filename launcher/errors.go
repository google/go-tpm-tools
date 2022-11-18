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
