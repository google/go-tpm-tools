package test

import _ "embed" // Necessary to use go:embed

// Raw binary TCG Event Logs
var (
	//go:embed eventlogs/arch-linux-workstation.bin
	ArchLinuxWorkstationEventLog []byte
	//go:embed eventlogs/debian-10.bin
	Debian10EventLog []byte
	//go:embed eventlogs/glinux-alex.bin
	GlinuxAlexEventLog []byte
	//go:embed eventlogs/rhel8-uefi.bin
	Rhel8EventLog []byte
	//go:embed eventlogs/ubuntu-1804-amd-sev.bin
	Ubuntu1804AmdSevEventLog []byte
	//go:embed eventlogs/ubuntu-2104-no-dbx.bin
	Ubuntu2104NoDbxEventLog []byte
	//go:embed eventlogs/ubuntu-2104-no-secure-boot.bin
	Ubuntu2104NoSecureBootEventLog []byte
	//go:embed eventlogs/cos-85-amd-sev.bin
	Cos85AmdSevEventLog []byte
	//go:embed eventlogs/cos-93-amd-sev.bin
	Cos93AmdSevEventLog []byte
	//go:embed eventlogs/cos-101-amd-sev.bin
	Cos101AmdSevEventLog []byte
)

// Kernel command lines from event logs.
var (
	Cos85AmdSevCmdline  = "/syslinux/vmlinuz.A init=/usr/lib/systemd/systemd boot=local rootwait ro noresume noswap loglevel=7 noinitrd console=ttyS0 security=apparmor virtio_net.napi_tx=1 systemd.unified_cgroup_hierarchy=false systemd.legacy_systemd_cgroup_controller=false csm.disabled=1 loadpin.exclude=kernel-module modules-load=loadpin_trigger module.sig_enforce=1 dm_verity.error_behavior=3 dm_verity.max_bios=-1 dm_verity.dev_wait=1 i915.modeset=1 cros_efi root=/dev/dm-0 \"dm=1 vroot none ro 1,0 4077568 verity payload=PARTUUID=EF8ECEE2-2385-AE4F-A146-1ED93D8AC217 hashtree=PARTUUID=EF8ECEE2-2385-AE4F-A146-1ED93D8AC217 hashstart=4077568 alg=sha256 root_hexdigest=795872ee03859c10dfcc4d67b4b96c85094b340c2d8784783abc2fa12a6ed671 salt=40eb77fb9093cbff56a6f9c2214c4f7554817d079513b7c77de4953d6b8ffc16\"\x00"
	Cos93AmdSevCmdline  = "/syslinux/vmlinuz.A init=/usr/lib/systemd/systemd boot=local rootwait ro noresume loglevel=7 noinitrd console=ttyS0 security=apparmor virtio_net.napi_tx=1 systemd.unified_cgroup_hierarchy=false systemd.legacy_systemd_cgroup_controller=false csm.disabled=1 loadpin.exclude=kernel-module modules-load=loadpin_trigger module.sig_enforce=1 console=tty1 dm_verity.error_behavior=3 dm_verity.max_bios=-1 dm_verity.dev_wait=1 i915.modeset=1 cros_efi root=/dev/dm-0 \"dm=1 vroot none ro 1,0 4077568 verity payload=PARTUUID=05CDEDEA-42C6-2248-B6B3-AB4CE3EA7501 hashtree=PARTUUID=05CDEDEA-42C6-2248-B6B3-AB4CE3EA7501 hashstart=4077568 alg=sha256 root_hexdigest=8db95edb446a7311634fc8409e6eab39c66886c4db16aeeef166bbd8fe4ff357 salt=3ec6b6fef69119253b9a5f79a5bb06bc7b12f177063b2466a04f08976375af44\"\x00"
	Cos101AmdSevCmdline = "/syslinux/vmlinuz.A init=/usr/lib/systemd/systemd boot=local rootwait ro noresume loglevel=7 console=tty1 console=ttyS0 security=apparmor virtio_net.napi_tx=1 nmi_watchdog=0 csm.disabled=1 loadpin.exclude=kernel-module modules-load=loadpin_trigger module.sig_enforce=1 dm_verity.error_behavior=3 dm_verity.max_bios=-1 dm_verity.dev_wait=1 i915.modeset=1 cros_efi root=/dev/dm-0 \"dm=1 vroot none ro 1,0 4077568 verity payload=PARTUUID=1D70214B-9AB3-E542-8372-3CCD786534FA hashtree=PARTUUID=1D70214B-9AB3-E542-8372-3CCD786534FA hashstart=4077568 alg=sha256 root_hexdigest=48d436350a7e83bde985cd3f7e79fa443557743b42243803ce31104ca4719c5d salt=b323b014b6f463172fca758a1c5a6745a2c8e5872be0e175e2f4b40c8295b2ab\"\x00"
)

// Attestation .pb files.
var (
	//go:embed attestations/gce-cos-85-no-nonce.pb
	COS85NoNonce []byte
	//go:embed attestations/gce-cos-85-nonce9009.pb
	COS85Nonce9009 []byte
)

// EK and AK Certificates.
var (
	//go:embed certificates/pca_tpm_ecc_enc_cert.pem
	GCEEncryptECCCertPCA []byte
	//go:embed certificates/pca_tpm_ecc_sign_cert.pem
	GCESignECCCertPCA []byte
	//go:embed certificates/pca_tpm_rsa_enc_cert.pem
	GCEEncryptRSACertPCA []byte
	//go:embed certificates/pca_tpm_rsa_sign_cert.pem
	GCESignRSACertPCA []byte

	//go:embed certificates/uca_tpm_ecc_enc_cert.pem
	GCEEncryptECCCertUCA []byte
	//go:embed certificates/uca_tpm_ecc_sign_cert.pem
	GCESignECCCertUCA []byte
	//go:embed certificates/uca_tpm_rsa_enc_cert.pem
	GCEEncryptRSACertUCA []byte
	//go:embed certificates/uca_tpm_rsa_sign_cert.pem
	GCESignRSACertUCA []byte
)

// GCECertPEMs provides a variety of GCE test certificates, including AK/EK,
// RSA/ECC, and PCA/UCA.
var GCECertPEMs = [][]byte{
	GCEEncryptECCCertPCA, GCESignECCCertPCA,
	GCEEncryptRSACertPCA, GCESignRSACertPCA,
	GCEEncryptECCCertUCA, GCESignECCCertUCA,
	GCEEncryptRSACertUCA, GCESignRSACertUCA,
}
