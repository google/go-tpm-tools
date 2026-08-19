package main

import (
	"errors"
	"strings"
	"testing"

	"github.com/google/go-tpm-tools/launcher"
	"github.com/google/go-tpm-tools/launcher/internal/experiments"
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

type fakeIntegrityVerifier struct {
	dmsetupLsOut    string
	dmsetupLsErr    error
	dmsetupTableOut map[string]string
	dmsetupTableErr map[string]error
	cryptsetupOut   map[string]string
	cryptsetupErr   map[string]error
}

func (f fakeIntegrityVerifier) DmsetupLs() (string, error) {
	return f.dmsetupLsOut, f.dmsetupLsErr
}

func (f fakeIntegrityVerifier) DmsetupTable(name string) (string, error) {
	if f.dmsetupTableErr != nil {
		if err := f.dmsetupTableErr[name]; err != nil {
			return "", err
		}
	}
	return f.dmsetupTableOut[name], nil
}

func (f fakeIntegrityVerifier) CryptsetupStatus(name string) (string, error) {
	if f.cryptsetupErr != nil {
		if err := f.cryptsetupErr[name]; err != nil {
			return "", err
		}
	}
	return f.cryptsetupOut[name], nil
}

type fakeMountVerifier struct {
	findmntOut map[string]string
	findmntErr map[string]error
}

func (f fakeMountVerifier) Findmnt(target string) (string, error) {
	if f.findmntErr != nil {
		if err := f.findmntErr[target]; err != nil {
			return "", err
		}
	}
	return f.findmntOut[target], nil
}

func TestVerifyDiskIntegrity(t *testing.T) {
	tests := []struct {
		name          string
		verifier      fakeIntegrityVerifier
		expectedError string
	}{
		{
			name: "success path",
			verifier: fakeIntegrityVerifier{
				dmsetupLsOut: `protected_stateful_partition (254:0)
protected_stateful_partition_crypt (254:1)
protected_stateful_partition_zero (254:2)`,
				dmsetupTableOut: map[string]string{
					"/dev/mapper/protected_stateful_partition":       "0 20971520 clone 254:99 254:1 254:2 8",
					"/dev/mapper/protected_stateful_partition_crypt": "0 20971520 integrity:28:aead capi:gcm(aes)-random",
				},
				cryptsetupOut: map[string]string{
					"vroot":   "/dev/mapper/vroot is active and is in use.",
					"oemroot": "/dev/mapper/oemroot is active and is in use.",
				},
			},
			expectedError: "",
		},
		{
			name: "dmsetup ls fails",
			verifier: fakeIntegrityVerifier{
				dmsetupLsErr: errors.New("command failed"),
			},
			expectedError: "failed to call `dmsetup ls`: command failed",
		},
		{
			name: "missing protected_stateful_partition",
			verifier: fakeIntegrityVerifier{
				dmsetupLsOut: `protected_stateful_partition_crypt (254:1)
protected_stateful_partition_zero (254:2)`,
			},
			expectedError: "failed to find /dev/mapper/protected_stateful_partition",
		},
		{
			name: "missing crypt partition",
			verifier: fakeIntegrityVerifier{
				dmsetupLsOut: `protected_stateful_partition (254:0)
protected_stateful_partition_zero (254:2)`,
			},
			expectedError: "failed to find /dev/mapper/protected_stateful_partition_crypt",
		},
		{
			name: "missing zero partition",
			verifier: fakeIntegrityVerifier{
				dmsetupLsOut: `protected_stateful_partition (254:0)
protected_stateful_partition_crypt (254:1)`,
			},
			expectedError: "failed to find /dev/mapper/protected_stateful_partition_zero",
		},
		{
			name: "dmsetup table clone fails",
			verifier: fakeIntegrityVerifier{
				dmsetupLsOut: `protected_stateful_partition (254:0)
protected_stateful_partition_crypt (254:1)
protected_stateful_partition_zero (254:2)`,
				dmsetupTableErr: map[string]error{
					"/dev/mapper/protected_stateful_partition": errors.New("table error"),
				},
			},
			expectedError: "failed to check /dev/mapper/protected_stateful_partition status: table error",
		},
		{
			name: "clone table wrong format",
			verifier: fakeIntegrityVerifier{
				dmsetupLsOut: `protected_stateful_partition (254:0)
protected_stateful_partition_crypt (254:1)
protected_stateful_partition_zero (254:2)`,
				dmsetupTableOut: map[string]string{
					"/dev/mapper/protected_stateful_partition": "0 20971520 clone",
				},
			},
			expectedError: "clone table does not match expected format",
		},
		{
			name: "not a dm-clone device",
			verifier: fakeIntegrityVerifier{
				dmsetupLsOut: `protected_stateful_partition (254:0)
protected_stateful_partition_crypt (254:1)
protected_stateful_partition_zero (254:2)`,
				dmsetupTableOut: map[string]string{
					"/dev/mapper/protected_stateful_partition": "0 20971520 linear 254:99 254:1 254:2 8",
				},
			},
			expectedError: "protected_stateful_partition is not a dm-clone device",
		},
		{
			name: "wrong destination device",
			verifier: fakeIntegrityVerifier{
				dmsetupLsOut: `protected_stateful_partition (254:0)
protected_stateful_partition_crypt (254:1)
protected_stateful_partition_zero (254:2)`,
				dmsetupTableOut: map[string]string{
					"/dev/mapper/protected_stateful_partition": "0 20971520 clone 254:99 254:99 254:2 8",
				},
			},
			expectedError: "does not have protected_stateful_partition_crypt as a destination device",
		},
		{
			name: "wrong source device",
			verifier: fakeIntegrityVerifier{
				dmsetupLsOut: `protected_stateful_partition (254:0)
protected_stateful_partition_crypt (254:1)
protected_stateful_partition_zero (254:2)`,
				dmsetupTableOut: map[string]string{
					"/dev/mapper/protected_stateful_partition": "0 20971520 clone 254:99 254:1 254:99 8",
				},
			},
			expectedError: "protected_stateful_partition protected_stateful_partition_zero as a source device",
		},
		{
			name: "crypt partition missing integrity",
			verifier: fakeIntegrityVerifier{
				dmsetupLsOut: `protected_stateful_partition (254:0)
protected_stateful_partition_crypt (254:1)
protected_stateful_partition_zero (254:2)`,
				dmsetupTableOut: map[string]string{
					"/dev/mapper/protected_stateful_partition":       "0 20971520 clone 254:99 254:1 254:2 8",
					"/dev/mapper/protected_stateful_partition_crypt": "0 20971520 crypt aes-gcm-random",
				},
			},
			expectedError: "stateful partition is not integrity protected",
		},
		{
			name: "crypt partition wrong cipher",
			verifier: fakeIntegrityVerifier{
				dmsetupLsOut: `protected_stateful_partition (254:0)
protected_stateful_partition_crypt (254:1)
protected_stateful_partition_zero (254:2)`,
				dmsetupTableOut: map[string]string{
					"/dev/mapper/protected_stateful_partition":       "0 20971520 clone 254:99 254:1 254:2 8",
					"/dev/mapper/protected_stateful_partition_crypt": "0 20971520 integrity:28:aead aes-gcm-random",
				},
			},
			expectedError: "stateful partition is not using the aes-gcm-random cipher",
		},
		{
			name: "vroot status fails",
			verifier: fakeIntegrityVerifier{
				dmsetupLsOut: `protected_stateful_partition (254:0)
protected_stateful_partition_crypt (254:1)
protected_stateful_partition_zero (254:2)`,
				dmsetupTableOut: map[string]string{
					"/dev/mapper/protected_stateful_partition":       "0 20971520 clone 254:99 254:1 254:2 8",
					"/dev/mapper/protected_stateful_partition_crypt": "0 20971520 integrity:28:aead capi:gcm(aes)-random",
				},
				cryptsetupErr: map[string]error{
					"vroot": errors.New("cryptsetup error"),
				},
			},
			expectedError: "failed to check vroot status: cryptsetup error",
		},
		{
			name: "vroot not active",
			verifier: fakeIntegrityVerifier{
				dmsetupLsOut: `protected_stateful_partition (254:0)
protected_stateful_partition_crypt (254:1)
protected_stateful_partition_zero (254:2)`,
				dmsetupTableOut: map[string]string{
					"/dev/mapper/protected_stateful_partition":       "0 20971520 clone 254:99 254:1 254:2 8",
					"/dev/mapper/protected_stateful_partition_crypt": "0 20971520 integrity:28:aead capi:gcm(aes)-random",
				},
				cryptsetupOut: map[string]string{
					"vroot":   "Device vroot is not active.",
					"oemroot": "/dev/mapper/oemroot is active and is in use.",
				},
			},
			expectedError: "/dev/mapper/vroot was not mounted correctly",
		},
		{
			name: "oemroot not active",
			verifier: fakeIntegrityVerifier{
				dmsetupLsOut: `protected_stateful_partition (254:0)
protected_stateful_partition_crypt (254:1)
protected_stateful_partition_zero (254:2)`,
				dmsetupTableOut: map[string]string{
					"/dev/mapper/protected_stateful_partition":       "0 20971520 clone 254:99 254:1 254:2 8",
					"/dev/mapper/protected_stateful_partition_crypt": "0 20971520 integrity:28:aead capi:gcm(aes)-random",
				},
				cryptsetupOut: map[string]string{
					"vroot":   "/dev/mapper/vroot is active and is in use.",
					"oemroot": "Device oemroot is inactive.",
				},
			},
			expectedError: "/dev/mapper/oemroot was not mounted correctly",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyDiskIntegrity(tc.verifier)
			if tc.expectedError == "" {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tc.expectedError)
				} else if !strings.Contains(err.Error(), tc.expectedError) {
					t.Errorf("expected error containing %q, got %v", tc.expectedError, err)
				}
			}
		})
	}
}

func TestVerifyMounts(t *testing.T) {
	tests := []struct {
		name          string
		launchSpec    spec.LaunchSpec
		verifier      fakeMountVerifier
		expectedError string
	}{
		{
			name:       "success path",
			launchSpec: spec.LaunchSpec{},
			verifier: fakeMountVerifier{
				findmntOut: map[string]string{
					"/dev/mapper/protected_stateful_partition": `/var/lib/containerd /dev/mapper/protected_stateful_partition[/var/lib/containerd] ext4 rw,nosuid,nodev,relatime,commit=30
/var/lib/google     /dev/mapper/protected_stateful_partition[/var/lib/google]     ext4 rw,nosuid,nodev,relatime,commit=30`,
					"tmpfs": "/tmp tmpfs tmpfs rw,nosuid,nodev",
				},
			},
			expectedError: "",
		},
		{
			name: "success path BC mode",
			launchSpec: spec.LaunchSpec{
				Experiments: experiments.Experiments{
					BcMode: true,
				},
			},
			verifier: fakeMountVerifier{
				findmntOut: map[string]string{
					"/dev/mapper/protected_stateful_partition": "/var/lib/containerd /dev/mapper/protected_stateful_partition[/var/lib/containerd] ext4 rw,nosuid,nodev,relatime,commit=30",
					"tmpfs": "/tmp tmpfs tmpfs rw,nosuid,nodev",
				},
			},
			expectedError: "",
		},
		{
			name:       "findmnt stateful fails",
			launchSpec: spec.LaunchSpec{},
			verifier: fakeMountVerifier{
				findmntErr: map[string]error{
					"/dev/mapper/protected_stateful_partition": errors.New("findmnt error"),
				},
			},
			expectedError: "failed to findmnt /dev/mapper/protected_stateful_partition: findmnt error",
		},
		{
			name:       "containerd missing",
			launchSpec: spec.LaunchSpec{},
			verifier: fakeMountVerifier{
				findmntOut: map[string]string{
					"/dev/mapper/protected_stateful_partition": "/var/lib/google     /dev/mapper/protected_stateful_partition[/var/lib/google]     ext4 rw,nosuid,nodev,relatime,commit=30",
					"tmpfs": "/tmp tmpfs tmpfs rw,nosuid,nodev",
				},
			},
			expectedError: "/var/lib/containerd was not mounted on the protected_stateful_partition",
		},
		{
			name:       "google missing (non-BC mode)",
			launchSpec: spec.LaunchSpec{},
			verifier: fakeMountVerifier{
				findmntOut: map[string]string{
					"/dev/mapper/protected_stateful_partition": "/var/lib/containerd /dev/mapper/protected_stateful_partition[/var/lib/containerd] ext4 rw,nosuid,nodev,relatime,commit=30",
					"tmpfs": "/tmp tmpfs tmpfs rw,nosuid,nodev",
				},
			},
			expectedError: "/var/lib/google was not mounted on the protected_stateful_partition",
		},
		{
			name:       "findmnt tmpfs fails",
			launchSpec: spec.LaunchSpec{},
			verifier: fakeMountVerifier{
				findmntOut: map[string]string{
					"/dev/mapper/protected_stateful_partition": `/var/lib/containerd /dev/mapper/protected_stateful_partition[/var/lib/containerd] ext4 rw,nosuid,nodev,relatime,commit=30
/var/lib/google     /dev/mapper/protected_stateful_partition[/var/lib/google]     ext4 rw,nosuid,nodev,relatime,commit=30`,
				},
				findmntErr: map[string]error{
					"tmpfs": errors.New("tmpfs error"),
				},
			},
			expectedError: "failed to findmnt tmpfs: tmpfs error",
		},
		{
			name:       "tmp missing on tmpfs",
			launchSpec: spec.LaunchSpec{},
			verifier: fakeMountVerifier{
				findmntOut: map[string]string{
					"/dev/mapper/protected_stateful_partition": `/var/lib/containerd /dev/mapper/protected_stateful_partition[/var/lib/containerd] ext4 rw,nosuid,nodev,relatime,commit=30
/var/lib/google     /dev/mapper/protected_stateful_partition[/var/lib/google]     ext4 rw,nosuid,nodev,relatime,commit=30`,
					"tmpfs": "",
				},
			},
			expectedError: "/tmp was not mounted on the tmpfs",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := verifyMounts(tc.launchSpec, tc.verifier)
			if tc.expectedError == "" {
				if err != nil {
					t.Errorf("expected no error, got %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("expected error containing %q, got nil", tc.expectedError)
				} else if !strings.Contains(err.Error(), tc.expectedError) {
					t.Errorf("expected error containing %q, got %v", tc.expectedError, err)
				}
			}
		})
	}
}
