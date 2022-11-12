package main

import (
	"errors"
	"testing"

	"github.com/google/go-tpm-tools/launcher"
	"github.com/google/go-tpm-tools/launcher/spec"
)

func TestGetExitCode(t *testing.T) {
	testcases := []struct {
		name               string
		isHardened         bool
		restartPolicy      spec.RestartPolicy
		err                error
		expectedReturnCode int
	}{
		// no error, debug image
		{
			"debug, always restart, nil error",
			false, spec.Always, nil, holdRC,
		},
		{
			"debug, never restart, nil error",
			false, spec.Never, nil, holdRC,
		},
		{
			"debug, onfailure restart, nil error",
			false, spec.OnFailure, nil, holdRC,
		},
		// no error, hardened image
		{
			"hardened, always restart, nil error",
			true, spec.Always, nil, rebootRC,
		},
		{
			"hardened, never restart, nil error",
			true, spec.Never, nil, successRC,
		},
		{
			"hardened, onfailure restart, nil error",
			true, spec.OnFailure, nil, successRC,
		},
		// retryable error, debug image
		{
			"debug, always restart, retryable error",
			false, spec.Always, &launcher.RetryableError{}, holdRC,
		},
		{
			"debug, never restart, retryable error",
			false, spec.Never, &launcher.RetryableError{}, holdRC,
		},
		{
			"debug, onfailure restart, retryable error",
			false, spec.OnFailure, &launcher.RetryableError{}, holdRC,
		},
		// workload error, debug image (same as retryable error)
		{
			"debug, always restart, workload error",
			false, spec.Always, &launcher.WorkloadError{}, holdRC,
		},
		{
			"debug, never restart, workload error",
			false, spec.Never, &launcher.WorkloadError{}, holdRC,
		},
		{
			"debug, onfailure restart, workload error",
			false, spec.OnFailure, &launcher.WorkloadError{}, holdRC,
		},
		// retryable error, hardened image
		{
			"hardened, always restart, retryable error",
			true, spec.Always, &launcher.RetryableError{}, rebootRC,
		},
		{
			"hardened, never restart, retryable error",
			true, spec.Never, &launcher.RetryableError{}, failRC,
		},
		{
			"hardened, onfailure restart, retryable error",
			true, spec.OnFailure, &launcher.RetryableError{}, rebootRC,
		},
		// workload error, hardened image (same as retryable error)
		{
			"hardened, always restart, workload error",
			true, spec.Always, &launcher.WorkloadError{}, rebootRC,
		},
		{
			"hardened, never restart, workload error",
			true, spec.Never, &launcher.WorkloadError{}, failRC,
		},
		{
			"hardened, onfailure restart, workload error",
			true, spec.OnFailure, &launcher.WorkloadError{}, rebootRC,
		},
		// non-retryable error, debug image
		{
			"debug, always restart, non-retryable error",
			false, spec.Always, errors.New(""), holdRC,
		},
		{
			"debug, never restart, non-retryable error",
			false, spec.Never, errors.New(""), holdRC,
		},
		{
			"debug, onfailure restart, non-retryable error",
			false, spec.OnFailure, errors.New(""), holdRC,
		},
		// non-retryable error, hardened image
		{
			"hardened, always restart, non-retryable error",
			true, spec.Always, errors.New(""), failRC,
		},
		{
			"hardened, never restart, non-retryable error",
			true, spec.Never, errors.New(""), failRC,
		},
		{
			"hardened, onfailure restart, non-retryable error",
			true, spec.OnFailure, errors.New(""), failRC,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			if rc := getExitCode(tc.isHardened, tc.restartPolicy, tc.err); rc != tc.expectedReturnCode {
				t.Errorf("got %d, wanted %d", rc, tc.expectedReturnCode)
			}
		})
	}
}
