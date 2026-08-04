// Package device provides an interface and management for device Root of Trust (ROT) attestation.
package device

import (
	"errors"
	"sync"
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

// ReadyStateEnabler is an optional interface implemented by devices (such as GPUs)
// that require transitioning to a runtime ready state after attestation collection.
type ReadyStateEnabler interface {
	// EnableReadyState enables the runtime ready state on the device.
	EnableReadyState() error
}

// ROTManager manages the attestation of all attached device ROTs.
type ROTManager struct {
	deviceMu     sync.Mutex
	rotsByVendor map[Vendor][]ROT
}

// ReportOpts defines the options for device attestation report generation.
// This struct is used instead of individual parameters to allow clean extensibility
// when supporting different accelerator types (e.g., TPUs, GPUs) in the future without breaking APIs.
type ReportOpts struct {
	// EnableRuntimeGPUAttestation indicates whether to include runtime GPU attestation in the device reports.
	EnableRuntimeGPUAttestation bool
}

// NewROTManager creates a new ROTManager.
func NewROTManager(rots []ROT) *ROTManager {
	m := &ROTManager{
		rotsByVendor: make(map[Vendor][]ROT),
	}
	for _, rot := range rots {
		if rot != nil {
			m.rotsByVendor[rot.Vendor()] = append(m.rotsByVendor[rot.Vendor()], rot)
		}
	}
	return m
}

// ValidateROTs validates attached device ROTs.
// Note: CS Launcher supports various vendor types simultaneously (e.g., NVIDIA GPUs,
// NIC devices from other vendors), so strict checks against vendor mixing are not enforced.
func (m *ROTManager) ValidateROTs() error {
	if m == nil {
		return nil
	}
	m.deviceMu.Lock()
	defer m.deviceMu.Unlock()
	return nil
}

// ROTs returns all managed device ROTs across all vendors.
func (m *ROTManager) ROTs() []ROT {
	if m == nil {
		return nil
	}
	m.deviceMu.Lock()
	defer m.deviceMu.Unlock()

	var all []ROT
	for _, rots := range m.rotsByVendor {
		all = append(all, rots...)
	}
	return all
}

// Lookup returns all managed device ROTs matching the given vendor.
func (m *ROTManager) Lookup(v Vendor) []ROT {
	if m == nil {
		return nil
	}
	m.deviceMu.Lock()
	defer m.deviceMu.Unlock()
	return m.rotsByVendor[v]
}

// filteredROTs returns the subset of device ROTs enabled by the provided report options.
func (m *ROTManager) filteredROTs(opts ReportOpts) []ROT {
	if m == nil {
		return nil
	}
	var filtered []ROT
	if opts.EnableRuntimeGPUAttestation {
		filtered = append(filtered, m.Lookup(NvidiaGPU)...)
	}
	return filtered
}

// AttestDeviceROTs fetches attestation reports from all detected device ROTs based on the provided options.
func (m *ROTManager) AttestDeviceROTs(nonce []byte, opts ReportOpts) ([]any, error) {
	if m == nil {
		return nil, nil
	}

	if err := m.ValidateROTs(); err != nil {
		return nil, err
	}

	var deviceReports []any
	var err error
	for _, deviceROT := range m.filteredROTs(opts) {
		deviceReport, e := deviceROT.Attest(nonce)
		if e != nil {
			err = errors.Join(err, e)
		} else {
			deviceReports = append(deviceReports, deviceReport)
		}
	}
	return deviceReports, err
}
