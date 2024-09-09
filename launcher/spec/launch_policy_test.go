package spec

import (
	"log"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm-tools/launcher/internal/launchermount"
)

func TestLaunchPolicy(t *testing.T) {
	testCases := []struct {
		testName       string
		imageLabels    map[string]string
		expectedPolicy LaunchPolicy
	}{
		{
			"single ENV override, CMD override",
			map[string]string{
				envOverride: "foo",
				cmdOverride: "true",
			},
			LaunchPolicy{
				AllowedEnvOverride: []string{"foo"},
				AllowedCmdOverride: true,
			},
		},
		{
			"multiple ENV override, no CMD override",
			map[string]string{
				envOverride: "foo,bar",
			},
			LaunchPolicy{
				AllowedEnvOverride: []string{"foo", "bar"},
				AllowedCmdOverride: false,
			},
		},
		{
			"no ENV override, no CMD override",
			nil,
			LaunchPolicy{
				AllowedEnvOverride: nil,
				AllowedCmdOverride: false,
			},
		},
		{
			"empty string in ENV override",
			map[string]string{
				envOverride: ",,,foo",
				cmdOverride: "false",
			},
			LaunchPolicy{
				AllowedEnvOverride: []string{"foo"},
				AllowedCmdOverride: false,
			},
		},
	}

	for _, testcase := range testCases {
		t.Run(testcase.testName, func(t *testing.T) {
			// Add default values for policy fields. Not relevant to tested behavior.
			testcase.expectedPolicy.HardenedImageMonitoring = none
			testcase.expectedPolicy.DebugImageMonitoring = health

			got, err := GetLaunchPolicy(testcase.imageLabels, log.Default())
			if err != nil {
				t.Fatal(err)
			}

			if !cmp.Equal(got, testcase.expectedPolicy) {
				t.Errorf("Launchspec got %+v, want %+v", got, testcase.expectedPolicy)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	testCases := []struct {
		testName  string
		policy    LaunchPolicy
		spec      LaunchSpec
		expectErr bool
	}{
		{
			"allows everything",
			LaunchPolicy{
				AllowedEnvOverride:      []string{"foo"},
				AllowedCmdOverride:      true,
				AllowedLogRedirect:      always,
				HardenedImageMonitoring: memoryOnly,
				DebugImageMonitoring:    memoryOnly,
			},
			LaunchSpec{
				Envs:                    []EnvVar{{Name: "foo", Value: "foo"}},
				Cmd:                     []string{"foo"},
				LogRedirect:             Everywhere,
				MemoryMonitoringEnabled: true,
			},
			false,
		},
		{
			"default case",
			LaunchPolicy{},
			LaunchSpec{},
			false,
		},
		{
			"env override violation",
			LaunchPolicy{
				AllowedEnvOverride: []string{"foo"},
			},
			LaunchSpec{
				Envs: []EnvVar{{Name: "bar", Value: ""}},
			},
			true,
		},
		{
			"cmd violation",
			LaunchPolicy{
				AllowedCmdOverride: false,
			},
			LaunchSpec{
				Cmd: []string{"foo"},
			},
			true,
		},
		{
			"log redirect (never, everywhere, hardened): err",
			LaunchPolicy{
				AllowedLogRedirect: never,
			},
			LaunchSpec{
				LogRedirect: Everywhere,
				Hardened:    true,
			},
			true,
		},
		{
			"log redirect (never, cloudlogging, hardened): err",
			LaunchPolicy{
				AllowedLogRedirect: never,
			},
			LaunchSpec{
				LogRedirect: CloudLogging,
				Hardened:    true,
			},
			true,
		},
		{
			"log redirect (never, serial, hardened): err",
			LaunchPolicy{
				AllowedLogRedirect: never,
			},
			LaunchSpec{
				LogRedirect: Serial,
				Hardened:    true,
			},
			true,
		},
		{
			"log redirect (never, nowhere, hardened): noerr",
			LaunchPolicy{
				AllowedLogRedirect: never,
			},
			LaunchSpec{
				LogRedirect: Nowhere,
				Hardened:    true,
			},
			false,
		},
		{
			"log redirect (never, everywhere, debug): err",
			LaunchPolicy{
				AllowedLogRedirect: never,
			},
			LaunchSpec{
				LogRedirect: Everywhere,
				Hardened:    false,
			},
			true,
		},
		{
			"log redirect (never, cloudlogging, debug): err",
			LaunchPolicy{
				AllowedLogRedirect: never,
			},
			LaunchSpec{
				LogRedirect: CloudLogging,
				Hardened:    false,
			},
			true,
		},
		{
			"log redirect (never, serial, debug): err",
			LaunchPolicy{
				AllowedLogRedirect: never,
			},
			LaunchSpec{
				LogRedirect: Serial,
				Hardened:    false,
			},
			true,
		},
		{
			"log redirect (never, nowhere, debug): noerr",
			LaunchPolicy{
				AllowedLogRedirect: never,
			},
			LaunchSpec{
				LogRedirect: Nowhere,
				Hardened:    false,
			},
			false,
		},
		{
			"log redirect (debugOnly, everywhere, hardened): err",
			LaunchPolicy{
				AllowedLogRedirect: debugOnly,
			},
			LaunchSpec{
				LogRedirect: Everywhere,
				Hardened:    true,
			},
			true,
		},
		{
			"log redirect (debugOnly, cloudlogging, hardened): err",
			LaunchPolicy{
				AllowedLogRedirect: debugOnly,
			},
			LaunchSpec{
				LogRedirect: CloudLogging,
				Hardened:    true,
			},
			true,
		},
		{
			"log redirect (debugOnly, serial, hardened): err",
			LaunchPolicy{
				AllowedLogRedirect: debugOnly,
			},
			LaunchSpec{
				LogRedirect: Serial,
				Hardened:    true,
			},
			true,
		},
		{
			"log redirect (debugOnly, nowhere, hardened): noerr",
			LaunchPolicy{
				AllowedLogRedirect: debugOnly,
			},
			LaunchSpec{
				LogRedirect: Nowhere,
				Hardened:    true,
			},
			false,
		},
		{
			"log redirect (debugOnly, everywhere, debug): noerr",
			LaunchPolicy{
				AllowedLogRedirect: debugOnly,
			},
			LaunchSpec{
				LogRedirect: Everywhere,
				Hardened:    false,
			},
			false,
		},
		{
			"log redirect (debugOnly, cloudlogging, debug): noerr",
			LaunchPolicy{
				AllowedLogRedirect: debugOnly,
			},
			LaunchSpec{
				LogRedirect: CloudLogging,
				Hardened:    false,
			},
			false,
		},
		{
			"log redirect (debugOnly, serial, debug): noerr",
			LaunchPolicy{
				AllowedLogRedirect: debugOnly,
			},
			LaunchSpec{
				LogRedirect: Serial,
				Hardened:    false,
			},
			false,
		},
		{
			"log redirect (debugOnly, nowhere, debug): noerr",
			LaunchPolicy{
				AllowedLogRedirect: debugOnly,
			},
			LaunchSpec{
				LogRedirect: Nowhere,
				Hardened:    false,
			},
			false,
		},
		{
			"log redirect (always, everywhere, hardened): noerr",
			LaunchPolicy{
				AllowedLogRedirect: always,
			},
			LaunchSpec{
				LogRedirect: Everywhere,
				Hardened:    true,
			},
			false,
		},
		{
			"log redirect (always, cloudlogging, hardened): noerr",
			LaunchPolicy{
				AllowedLogRedirect: always,
			},
			LaunchSpec{
				LogRedirect: CloudLogging,
				Hardened:    true,
			},
			false,
		},
		{
			"log redirect (always, serial, hardened): noerr",
			LaunchPolicy{
				AllowedLogRedirect: always,
			},
			LaunchSpec{
				LogRedirect: Serial,
				Hardened:    true,
			},
			false,
		},
		{
			"log redirect (always, nowhere, hardened): noerr",
			LaunchPolicy{
				AllowedLogRedirect: always,
			},
			LaunchSpec{
				LogRedirect: Nowhere,
				Hardened:    true,
			},
			false,
		},
		{
			"log redirect (always, everywhere, debug): noerr",
			LaunchPolicy{
				AllowedLogRedirect: always,
			},
			LaunchSpec{
				LogRedirect: Everywhere,
				Hardened:    false,
			},
			false,
		},
		{
			"log redirect (always, cloudlogging, debug): noerr",
			LaunchPolicy{
				AllowedLogRedirect: always,
			},
			LaunchSpec{
				LogRedirect: CloudLogging,
				Hardened:    false,
			},
			false,
		},
		{
			"log redirect (always, serial, debug): noerr",
			LaunchPolicy{
				AllowedLogRedirect: always,
			},
			LaunchSpec{
				LogRedirect: Serial,
				Hardened:    false,
			},
			false,
		},
		{
			"log redirect (always, nowhere, debug): noerr",
			LaunchPolicy{
				AllowedLogRedirect: always,
			},
			LaunchSpec{
				LogRedirect: Nowhere,
				Hardened:    false,
			},
			false,
		},
		{
			"allowed mount dest",
			LaunchPolicy{
				AllowedMountDestinations: []string{"/a"},
			},
			LaunchSpec{
				Mounts: []launchermount.Mount{
					launchermount.TmpfsMount{Destination: "/a/b"},
				},
			},
			false,
		},
		{
			"allowed mount dest same dir",
			LaunchPolicy{
				AllowedMountDestinations: []string{"/a"},
			},
			LaunchSpec{
				Mounts: []launchermount.Mount{
					launchermount.TmpfsMount{Destination: "/a"},
				},
			},
			false,
		},
		{
			"allowed mount dest multiple",
			LaunchPolicy{
				AllowedMountDestinations: []string{"/a", "/b", "/c/d"},
			},
			LaunchSpec{
				Mounts: []launchermount.Mount{
					launchermount.TmpfsMount{Destination: "/a"},
					launchermount.TmpfsMount{Destination: "/b"},
					launchermount.TmpfsMount{Destination: "/c/d"},
					launchermount.TmpfsMount{Destination: "/a/b"},
					launchermount.TmpfsMount{Destination: "/a/b/c"},
					launchermount.TmpfsMount{Destination: "/c/d/e"},
					launchermount.TmpfsMount{Destination: "/c/d/f"},
					launchermount.TmpfsMount{Destination: "/c/d/e/f/g/../b"},
					launchermount.TmpfsMount{Destination: "/c/d/e/f/./../b"},
					launchermount.TmpfsMount{Destination: "/c/d/e/f/./../../b"},
				},
			},
			false,
		},
		{
			"mount dest relative",
			LaunchPolicy{
				AllowedMountDestinations: []string{"/b"},
			},
			LaunchSpec{
				Mounts: []launchermount.Mount{
					launchermount.TmpfsMount{Destination: "/a/../b"},
				},
			},
			false,
		},
		{
			"mount dest not abs",
			LaunchPolicy{
				AllowedMountDestinations: []string{"/as"},
			},
			LaunchSpec{
				Mounts: []launchermount.Mount{
					launchermount.TmpfsMount{Destination: "asd"},
				},
			},
			true,
		},
		{
			"allowed mount dest not abs",
			LaunchPolicy{
				AllowedMountDestinations: []string{"as"},
			},
			LaunchSpec{
				Mounts: []launchermount.Mount{
					launchermount.TmpfsMount{Destination: "/asd"},
				},
			},
			true,
		},
		{
			"mount dest prefix but not subdir",
			LaunchPolicy{
				AllowedMountDestinations: []string{"/a"},
			},
			LaunchSpec{
				Mounts: []launchermount.Mount{
					launchermount.TmpfsMount{Destination: "/abcd"},
				},
			},
			true,
		},
		{
			"mount dest parent of allowed",
			LaunchPolicy{
				AllowedMountDestinations: []string{"/a/b"},
			},
			LaunchSpec{
				Mounts: []launchermount.Mount{
					launchermount.TmpfsMount{Destination: "/a"},
				},
			},
			true,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.testName, func(t *testing.T) {
			err := testCase.policy.Verify(testCase.spec)
			if testCase.expectErr {
				if err == nil {
					t.Errorf("expected error, but got nil")
				}
			} else {
				if err != nil {
					t.Errorf("expected no error, but got %v", err)
				}
			}
		})
	}
}

func TestVerifyMonitoringSettings(t *testing.T) {
	testCases := []struct {
		testName   string
		monitoring monitoringType
		spec       LaunchSpec
	}{
		{
			"none policy, disabled by spec",
			none,
			LaunchSpec{
				HealthMonitoringEnabled: false,
				MemoryMonitoringEnabled: false,
				LogRedirect:             Nowhere,
			},
		},
		{
			"memory-only policy, all disabled by spec",
			memoryOnly,
			LaunchSpec{
				HealthMonitoringEnabled: false,
				MemoryMonitoringEnabled: false,
				LogRedirect:             Nowhere,
			},
		},
		{
			"memory-only policy, memory enabled by spec",
			memoryOnly,
			LaunchSpec{
				MemoryMonitoringEnabled: true,
				LogRedirect:             Nowhere,
			},
		},
		{
			"health policy, health enabled by spec",
			health,
			LaunchSpec{
				HealthMonitoringEnabled: true,
				LogRedirect:             Nowhere,
			},
		},
		{
			"health policy, health disabled by spec",
			health,
			LaunchSpec{
				HealthMonitoringEnabled: false,
				LogRedirect:             Nowhere,
			},
		},
		{
			"health policy, memory enabled by spec",
			health,
			LaunchSpec{
				MemoryMonitoringEnabled: true,
				LogRedirect:             Nowhere,
			},
		},
		{
			"health policy, memory disabled by spec",
			health,
			LaunchSpec{
				MemoryMonitoringEnabled: false,
				LogRedirect:             Nowhere,
			},
		},
	}

	for _, testCase := range testCases {
		// Debug.
		t.Run("[Debug] "+testCase.testName, func(t *testing.T) {
			policy := LaunchPolicy{
				DebugImageMonitoring: testCase.monitoring,
			}
			if err := policy.Verify(testCase.spec); err != nil {
				t.Errorf("expected no error, but got %v", err)
			}
		})

		// Hardened.
		t.Run("[Hardened] "+testCase.testName, func(t *testing.T) {
			policy := LaunchPolicy{
				HardenedImageMonitoring: testCase.monitoring,
			}

			// Copy the spec and set Hardened=true.
			spec := testCase.spec
			spec.Hardened = true
			if err := policy.Verify(spec); err != nil {
				t.Errorf("expected no error, but got %v", err)
			}
		})
	}
}

func TestVerifyMonitoringSettingsErrors(t *testing.T) {
	testCases := []struct {
		testName   string
		monitoring monitoringType
		spec       LaunchSpec
	}{
		{
			"[Hardened] disabled policy, Health enabled by spec",
			none,
			LaunchSpec{
				HealthMonitoringEnabled: true,
				Hardened:                true,
				LogRedirect:             Nowhere,
			},
		},
		{
			"[Hardened] disabled policy, Memory enabled by spec",
			none,
			LaunchSpec{
				MemoryMonitoringEnabled: true,
				Hardened:                true,
				LogRedirect:             Nowhere,
			},
		},
		{
			"[Hardened] memory-only policy, Health enabled by spec",
			memoryOnly,
			LaunchSpec{
				HealthMonitoringEnabled: true,
				Hardened:                true,
				LogRedirect:             Nowhere,
			},
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.testName, func(t *testing.T) {
			// Debug.
			t.Run("[Debug] "+testCase.testName, func(t *testing.T) {
				policy := LaunchPolicy{
					DebugImageMonitoring: testCase.monitoring,
				}
				if err := policy.Verify(testCase.spec); err == nil {
					t.Errorf("expected error, but got nil")
				}
			})

			// Hardened.
			t.Run("[Hardened] "+testCase.testName, func(t *testing.T) {
				policy := LaunchPolicy{
					HardenedImageMonitoring: testCase.monitoring,
				}

				// Copy the spec and set Hardened=true.
				spec := testCase.spec
				spec.Hardened = true
				if err := policy.Verify(spec); err == nil {
					t.Errorf("expected error, but got nil")
				}
			})
		})
	}
}

func TestIsHardened(t *testing.T) {
	testCases := []struct {
		testName       string
		kernelCmd      string
		expectHardened bool
	}{
		{
			"empty kernel cmd",
			"",
			false,
		},
		{
			"no confidential-space.hardened arg",
			"BOOT_IMAGE=/syslinux/vmlinuz.B init=/usr/lib/systemd/systemd boot=local rootwait ro noresume loglevel=7 console=tty1 console=ttyS0 security=apparmor virtio_net.napi_tx=1 nmi_watchdog=0 csm.disabled=1 loadpin.exclude=kernel-module modules-load=loadpin_trigger module.sig_enforce=1 dm_verity.error_behavior=3 dm_verity.max_bios=-1 dm_verity.dev_wait=1 i915.modeset=1 cros_efi cos.protected_stateful_partition=e systemd.mask=update-engine.service ds=nocloud;s=/usr/share/oem/ cros_debug root=/dev/dm-0 \"dm=2 vroot none ro 1,0 4077568 verity payload=PARTUUID=DC7DB0DC-DDCC-AA45-BAE3-A41CA1698E83 hashtree=PARTUUID=DC7DB0DC-DDCC-AA45-BAE3-A41CA1698E83 hashstart=4077568 alg=sha256 root_hexdigest=6d5887660805db1b366319bd1c2161600d11b9e53f059b0e44b760a7277e1b0a salt=f4a41993832655a00d48f5769351370bebafd7de906df068bc1b1929b175ee43,oemroot none ro 1, 0 1024000 verity payload=PARTUUID=fd5af56a-7b25-c448-a616-19eb240b3260 hashtree=PARTUUID=fd5af56a-7b25-c448-a616-19eb240b3260 hashstart=1024000 alg=sha256 root_hexdigest=50c406c129054649a432fa144eeff56aa8b707d4c86f3ab44edde589356e8b23 salt=2a3461269a26ad6247f4b64cacd84f64e5a3311cd4b2f742bab6442291bf4977\"",
			false,
		},
		{
			"has kernel arg confidential-space.hardened=true",
			"BOOT_IMAGE=/syslinux/vmlinuz.B init=/usr/lib/systemd/systemd boot=local rootwait ro noresume loglevel=7 console=tty1 console=ttyS0 security=apparmor virtio_net.napi_tx=1 nmi_watchdog=0 csm.disabled=1 loadpin.exclude=kernel-module modules-load=loadpin_trigger module.sig_enforce=1 dm_verity.error_behavior=3 dm_verity.max_bios=-1 dm_verity.dev_wait=1 i915.modeset=1 cros_efi confidential-space.hardened=true cos.protected_stateful_partition=e systemd.mask=update-engine.service ds=nocloud;s=/usr/share/oem/ cros_debug root=/dev/dm-0 \"dm=2 vroot none ro 1,0 4077568 verity payload=PARTUUID=DC7DB0DC-DDCC-AA45-BAE3-A41CA1698E83 hashtree=PARTUUID=DC7DB0DC-DDCC-AA45-BAE3-A41CA1698E83 hashstart=4077568 alg=sha256 root_hexdigest=6d5887660805db1b366319bd1c2161600d11b9e53f059b0e44b760a7277e1b0a salt=f4a41993832655a00d48f5769351370bebafd7de906df068bc1b1929b175ee43,oemroot none ro 1, 0 1024000 verity payload=PARTUUID=fd5af56a-7b25-c448-a616-19eb240b3260 hashtree=PARTUUID=fd5af56a-7b25-c448-a616-19eb240b3260 hashstart=1024000 alg=sha256 root_hexdigest=50c406c129054649a432fa144eeff56aa8b707d4c86f3ab44edde589356e8b23 salt=2a3461269a26ad6247f4b64cacd84f64e5a3311cd4b2f742bab6442291bf4977\"",
			true,
		},
		{
			"has kernel arg confidential-space.hardened=false",
			"BOOT_IMAGE=/syslinux/vmlinuz.B init=/usr/lib/systemd/systemd boot=local rootwait ro noresume loglevel=7 console=tty1 console=ttyS0 security=apparmor virtio_net.napi_tx=1 nmi_watchdog=0 csm.disabled=1 loadpin.exclude=kernel-module modules-load=loadpin_trigger module.sig_enforce=1 dm_verity.error_behavior=3 dm_verity.max_bios=-1 dm_verity.dev_wait=1 i915.modeset=1 cros_efi confidential-space.hardened=false cos.protected_stateful_partition=e systemd.mask=update-engine.service ds=nocloud;s=/usr/share/oem/ cros_debug root=/dev/dm-0 \"dm=2 vroot none ro 1,0 4077568 verity payload=PARTUUID=DC7DB0DC-DDCC-AA45-BAE3-A41CA1698E83 hashtree=PARTUUID=DC7DB0DC-DDCC-AA45-BAE3-A41CA1698E83 hashstart=4077568 alg=sha256 root_hexdigest=6d5887660805db1b366319bd1c2161600d11b9e53f059b0e44b760a7277e1b0a salt=f4a41993832655a00d48f5769351370bebafd7de906df068bc1b1929b175ee43,oemroot none ro 1, 0 1024000 verity payload=PARTUUID=fd5af56a-7b25-c448-a616-19eb240b3260 hashtree=PARTUUID=fd5af56a-7b25-c448-a616-19eb240b3260 hashstart=1024000 alg=sha256 root_hexdigest=50c406c129054649a432fa144eeff56aa8b707d4c86f3ab44edde589356e8b23 salt=2a3461269a26ad6247f4b64cacd84f64e5a3311cd4b2f742bab6442291bf4977\"",
			false,
		},
	}

	for _, testCase := range testCases {
		t.Run(testCase.testName, func(t *testing.T) {
			hardened := isHardened(testCase.kernelCmd)
			if testCase.expectHardened != hardened {
				t.Errorf("expected %t, but got %t", testCase.expectHardened, hardened)
			}
		})
	}
}

func TestGetMonitoringPolicy(t *testing.T) {
	testcases := []struct {
		name           string
		labels         map[string]string
		expectedPolicy *LaunchPolicy
	}{
		{
			name: "memory_monitoring_allow=always",
			labels: map[string]string{
				memoryMonitoring: "always",
			},
			expectedPolicy: &LaunchPolicy{
				HardenedImageMonitoring: memoryOnly,
				DebugImageMonitoring:    memoryOnly,
			},
		},
		{
			name: "memory_monitoring_allow=never",
			labels: map[string]string{
				memoryMonitoring: "never",
			},
			expectedPolicy: &LaunchPolicy{
				HardenedImageMonitoring: none,
				DebugImageMonitoring:    none,
			},
		},
		{
			name: "memory_monitoring_allow=debugonly",
			labels: map[string]string{
				memoryMonitoring: "debugonly",
			},
			expectedPolicy: &LaunchPolicy{
				HardenedImageMonitoring: none,
				DebugImageMonitoring:    memoryOnly,
			},
		},
		{
			name: "HardenedImageMonitoring=none",
			labels: map[string]string{
				hardenedMonitoring: "none",
			},
			expectedPolicy: &LaunchPolicy{
				HardenedImageMonitoring: none,
				DebugImageMonitoring:    health,
			},
		},
		{
			name: "HardenedImageMonitoring=memoryonly",
			labels: map[string]string{
				hardenedMonitoring: "memoryonly",
			},
			expectedPolicy: &LaunchPolicy{
				HardenedImageMonitoring: memoryOnly,
				DebugImageMonitoring:    health,
			},
		},
		{
			name: "HardenedImageMonitoring=health",
			labels: map[string]string{
				hardenedMonitoring: "health",
			},
			expectedPolicy: &LaunchPolicy{
				HardenedImageMonitoring: health,
				DebugImageMonitoring:    health,
			},
		},
		{
			name: "DebugImageMonitoring=none",
			labels: map[string]string{
				debugMonitoring: "none",
			},
			expectedPolicy: &LaunchPolicy{
				HardenedImageMonitoring: none,
				DebugImageMonitoring:    none,
			},
		},
		{
			name: "DebugImageMonitoring=memoryonly",
			labels: map[string]string{
				debugMonitoring: "memoryonly",
			},
			expectedPolicy: &LaunchPolicy{
				HardenedImageMonitoring: none,
				DebugImageMonitoring:    memoryOnly,
			},
		},
		{
			name: "DebugImageMonitoring=health",
			labels: map[string]string{
				debugMonitoring: "health",
			},
			expectedPolicy: &LaunchPolicy{
				HardenedImageMonitoring: none,
				DebugImageMonitoring:    health,
			},
		},
		// Set both fields to non-default values.
		{
			name: "HardenedImageMonitoring=health, DebugImageMonitoring=none",
			labels: map[string]string{
				hardenedMonitoring: "health",
				debugMonitoring:    "none",
			},
			expectedPolicy: &LaunchPolicy{
				HardenedImageMonitoring: health,
				DebugImageMonitoring:    none,
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			policy := &LaunchPolicy{}
			if err := configureMonitoringPolicy(tc.labels, policy, log.Default()); err != nil {
				t.Errorf("getMonitoringPolicy returned error: %v", err)
				return
			}

			if !cmp.Equal(policy, tc.expectedPolicy) {
				t.Errorf("getMonitoringPolicy did not return expected policy: got %v, want %v", policy, tc.expectedPolicy)
			}
		})
	}
}

func TestGetMonitoringPolicyErrors(t *testing.T) {
	testcases := []struct {
		name   string
		labels map[string]string
	}{
		{
			name: "memory_monitoring_allow and hardened_monitoring specified",
			labels: map[string]string{
				memoryMonitoring:   "always",
				hardenedMonitoring: "health",
			},
		},
		{
			name: "memory_monitoring_allow and debug_monitoring specified",
			labels: map[string]string{
				memoryMonitoring: "always",
				debugMonitoring:  "health",
			},
		},
		{
			name: "memory_monitoring_allow, hardened_monitoring, and debug_monitoring specified",
			labels: map[string]string{
				memoryMonitoring:   "always",
				hardenedMonitoring: "health",
				debugMonitoring:    "memoryOnly",
			},
		},
		{
			name: "invalid value for memory_monitoring_allow",
			labels: map[string]string{
				memoryMonitoring: "this is not valid",
			},
		},
		{
			name: "invalid value for hardened_monitoring",
			labels: map[string]string{
				hardenedMonitoring: "this is not valid",
			},
		},
		{
			name: "invalid value for debug_monitoring",
			labels: map[string]string{
				debugMonitoring: "this is not valid",
			},
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			policy := &LaunchPolicy{}
			if err := configureMonitoringPolicy(tc.labels, policy, log.Default()); err == nil {
				t.Errorf("Expected getMonitoringPolicy to return error, returned successfully with policy %v", policy)
			}
		})
	}
}
