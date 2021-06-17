// +build !linux

package client

import "errors"

// GetEventLog grabs the crypto-agile TCG event log for the system.
func GetEventLog() ([]byte, error) {
	return nil, errors.New("failed to get event log: only Linux supported")
}
