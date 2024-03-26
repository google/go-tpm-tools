package client

import "os"

// EventLogPath specifies the event log location
var EventLogPath = "/sys/kernel/security/tpm0/binary_bios_measurements"

func getRealEventLog() ([]byte, error) {
	return os.ReadFile(EventLogPath)
}
