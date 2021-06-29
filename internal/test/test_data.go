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
	//go:embed eventlogs/ubuntu-2104-no-dbx.bin
	Ubuntu2104NoDbxEventLog []byte
	//go:embed eventlogs/ubuntu-2104-no-secure-boot.bin
	Ubuntu2104NoSecureBootEventLog []byte
)
