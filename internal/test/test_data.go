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
)

// Attestation .pb files.
var (
	//go:embed attestations/gce-cos-85-no-nonce.pb
	COS85NoNonce []byte
	//go:embed attestations/gce-cos-85-nonce9009.pb
	COS85Nonce9009 []byte
)
