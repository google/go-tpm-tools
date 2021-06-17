package client

import (
	"io/ioutil"
)

// GetEventLog grabs the crypto-agile TCG event log for the system.
func GetEventLog() ([]byte, error) {
	return ioutil.ReadFile("/sys/kernel/security/tpm0/binary_bios_measurements")
}
