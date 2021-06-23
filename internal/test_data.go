package internal

import (
	_ "embed"
)

//go:embed eventlogs/debian-10.bin
var Debian10EventLog []byte

//go:embed eventlogs/rhel8-uefi.bin
var Rhel8EventLog []byte

//go:embed eventlogs/ubuntu-2104.bin
var Ubuntu2104EventLog []byte
