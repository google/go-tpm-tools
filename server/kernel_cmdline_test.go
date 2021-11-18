package server

import (
	"testing"
)

// Extracted from Cos85AmdSevEventLog (internal/test/eventlogs/cos-85-amd-sev.bin).
// kernel_cmdline: /syslinux/vmlinuz.A init=/usr/lib/systemd/systemd boot=local rootwait ro noresume noswap loglevel=7 noinitrd console=ttyS0 security=apparmor virtio_net.napi_tx=1 systemd.unified_cgroup_hierarchy=false systemd.legacy_systemd_cgroup_controller=false csm.disabled=1 loadpin.exclude=kernel-module modules-load=loadpin_trigger module.sig_enforce=1 dm_verity.error_behavior=3 dm_verity.max_bios=-1 dm_verity.dev_wait=1 i915.modeset=1 cros_efi root=/dev/dm-0 "dm=1 vroot none ro 1,0 4077568 verity payload=PARTUUID=EF8ECEE2-2385-AE4F-A146-1ED93D8AC217 hashtree=PARTUUID=EF8ECEE2-2385-AE4F-A146-1ED93D8AC217 hashstart=4077568 alg=sha256 root_hexdigest=795872ee03859c10dfcc4d67b4b96c85094b340c2d8784783abc2fa12a6ed671 salt=40eb77fb9093cbff56a6f9c2214c4f7554817d079513b7c77de4953d6b8ffc16"%
var (
	cosKernelCmdline = "6b65726e656c5f636d646c696e653a202f7379736c696e75782f766d6c696e757a2e4120696e69743d2f7573722f6c69622f73797374656d642f73797374656d6420626f6f743d6c6f63616c20726f6f747761697420726f206e6f726573756d65206e6f73776170206c6f676c6576656c3d37206e6f696e6974726420636f6e736f6c653d74747953302073656375726974793d61707061726d6f722076697274696f5f6e65742e6e6170695f74783d312073797374656d642e756e69666965645f6367726f75705f6869657261726368793d66616c73652073797374656d642e6c65676163795f73797374656d645f6367726f75705f636f6e74726f6c6c65723d66616c73652063736d2e64697361626c65643d31206c6f616470696e2e6578636c7564653d6b65726e656c2d6d6f64756c65206d6f64756c65732d6c6f61643d6c6f616470696e5f74726967676572206d6f64756c652e7369675f656e666f7263653d3120646d5f7665726974792e6572726f725f6265686176696f723d3320646d5f7665726974792e6d61785f62696f733d2d3120646d5f7665726974792e6465765f776169743d3120693931352e6d6f64657365743d312063726f735f65666920726f6f743d2f6465762f646d2d302022646d3d312076726f6f74206e6f6e6520726f20312c30203430373735363820766572697479207061796c6f61643d50415254555549443d45463845434545322d323338352d414534462d413134362d3145443933443841433231372068617368747265653d50415254555549443d45463845434545322d323338352d414534462d413134362d314544393344384143323137206861736873746172743d3430373735363820616c673d73686132353620726f6f745f6865786469676573743d373935383732656530333835396331306466636334643637623462393663383530393462333430633264383738343738336162633266613132613665643637312073616c743d343065623737666239303933636266663536613666396332323134633466373535343831376430373935313362376337376465343935336436623866666331362200"
	expectedDmFlag   = "1 vroot none ro 1,0 4077568 verity payload=PARTUUID=EF8ECEE2-2385-AE4F-A146-1ED93D8AC217 hashtree=PARTUUID=EF8ECEE2-2385-AE4F-A146-1ED93D8AC217 hashstart=4077568 alg=sha256 root_hexdigest=795872ee03859c10dfcc4d67b4b96c85094b340c2d8784783abc2fa12a6ed671 salt=40eb77fb9093cbff56a6f9c2214c4f7554817d079513b7c77de4953d6b8ffc16"
)

func TestParseArgsRealCmdline(t *testing.T) {
	cmdlineBytes := decodeHex(cosKernelCmdline)
	// Remove the GRUB prefix.
	cmdlineBytes = cmdlineBytes[len(newGrubKernelCmdlinePrefix):]
	paramsToVals := parseArgs(cmdlineBytes)

	if paramsToVals["init"] != "/usr/lib/systemd/systemd" {
		t.Errorf("expected exact init arg!")
	}
	if paramsToVals["noinitrd"] != "" {
		t.Errorf("expected exact noinitrd arg!")
	}
	if paramsToVals["nonexistent"] != "" {
		t.Errorf("expected this flag to not exist!")
	}
	if paramsToVals["dm"] != expectedDmFlag {
		t.Errorf("expected exact dm arg!")
	}
}

func TestParseArgs(t *testing.T) {
	tests := []struct {
		name    string
		cmdline []byte
	}{
		{"COS-CommandLine", decodeHex(cosKernelCmdline)},
		{"Empty", []byte{}},
		{"NullTerminator", []byte{0x00}},
		{"UnbalancedQuote", []byte{0x22, 0x00}},
		{"UnbalancedQuote-NoNull", []byte{0x22}},
		{"BalancedQuote", []byte{0x22, 0x22, 0x00}},
		{"BalancedQuote-NoNull", []byte{0x22, 0x22}},
		{"ManyNulls", []byte{0x00, 0x00, 0x00, 0x00}},
		{"ManyQuotes", []byte{0x22, 0x22, 0x22, 0x22, 0x00}},
		{"ManyUnbalancedQuotes", []byte{0x22, 0x22, 0x22, 0x22, 0x22, 0x00}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// Ensure no panics.
			parseArgs(test.cmdline)
		})
	}
}
