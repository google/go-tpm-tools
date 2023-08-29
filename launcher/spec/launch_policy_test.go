package spec

import (
	"testing"

	"github.com/google/go-cmp/cmp"
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
			got, err := GetLaunchPolicy(testcase.imageLabels)
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
				AllowedEnvOverride: []string{"foo"},
				AllowedCmdOverride: true,
				AllowedLogRedirect: always,
			},
			LaunchSpec{
				Envs:        []EnvVar{{Name: "foo", Value: "foo"}},
				Cmd:         []string{"foo"},
				LogRedirect: Everywhere,
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
