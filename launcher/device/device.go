// Package device provides an interface and management for device Root of Trust (ROT) attestation in the launcher.
package device

import (
	"sync"

	"go.uber.org/multierr"
)

// Vendor defines the type for device Root of Trust (ROT) vendors.
type Vendor int

// Define constants for supported ROT vendors.
const (
	Unspecified Vendor = iota
	NvidiaGPU
)

// ROT defines an interface for all attached devices to collect attestation.
type ROT interface {
	// Attest fetches an attestation from the attached device detected by launcher.
	Attest(nonce []byte) (any, error)
	// Vendor returns the device ROT vendor type.
	Vendor() Vendor
}

// ROTManager manages the attestation of all attached device ROTs.
type ROTManager struct {
	deviceMu sync.Mutex
	rots     []ROT
}

// ReportOpts defines the options for device attestation report generation.
type ReportOpts struct {
	// EnableRuntimeGPUAttestation indicates whether to include runtime GPU attestation in the device reports.
	EnableRuntimeGPUAttestation bool
}

// NewROTManager creates a new ROTManager.
func NewROTManager(rots []ROT) *ROTManager {
	return &ROTManager{
		rots: rots,
	}
}

// AttestDeviceROTs fetches attestation reports from all detected device ROTs based on the provided options.
func (m *ROTManager) AttestDeviceROTs(nonce []byte, opts ReportOpts) ([]any, error) {
	m.deviceMu.Lock()
	defer m.deviceMu.Unlock()

	var deviceReports []any
	var err error
	for _, deviceROT := range m.rots {
		if opts.EnableRuntimeGPUAttestation && deviceROT.Vendor() == NvidiaGPU {
			deviceReport, e := deviceROT.Attest(nonce)
			if e != nil {
				err = multierr.Append(err, e)
			} else {
				deviceReports = append(deviceReports, deviceReport)
			}
		}
	}
	return deviceReports, err
}
