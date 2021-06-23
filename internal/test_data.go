package internal

import (
	_ "embed"
)

//go:embed eventlogs/arch-linux-workstation.bin
var ArchLinuxWorkstationEventLog []byte

//go:embed eventlogs/debian-10.bin
var Debian10EventLog []byte

//go:embed eventlogs/glinux-alex.bin
var GlinuxAlexEventLog []byte

//go:embed eventlogs/rhel8-uefi.bin
var Rhel8EventLog []byte

//go:embed eventlogs/ubuntu-2104-no-dbx.bin
var Ubuntu2104NoDbxEventLog []byte

//go:embed eventlogs/ubuntu-2104-no-secure-boot.bin
var Ubuntu2104NoSecureBootEventLog []byte
