// Package device provides an interface and management for device Root of Trust (ROT) attestation.
package device

import (
	"errors"
	"fmt"
	"sync"

	"google.golang.org/protobuf/proto"

	attestationpb "github.com/GoogleCloudPlatform/confidential-space/server/proto/gen/attestation"
	gecel "github.com/google/go-eventlog/cel"
	"github.com/google/go-tpm-tools/cel"
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

// EventMeasurer defines the interface for measuring events into an event log (CEL).
type EventMeasurer interface {
	MeasureEvent(event gecel.Content) error
}

// ROTManager manages the attestation of all attached device ROTs.
type ROTManager struct {
	deviceMu sync.Mutex
	rots     []ROT
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
	return &ROTManager{
		rots: rots,
	}
}

func (m *ROTManager) validateROTs() error {
	if len(m.rots) <= 1 {
		return nil
	}
	firstVendor := m.rots[0].Vendor()
	for _, rot := range m.rots[1:] {
		if rot.Vendor() != firstVendor {
			return fmt.Errorf("multiple different device ROT vendors detected (%v and %v): only one accelerator type per boot sequence is supported", firstVendor, rot.Vendor())
		}
	}
	return nil
}

// AttestDeviceROTs fetches attestation reports from all detected device ROTs based on the provided options.
func (m *ROTManager) AttestDeviceROTs(nonce []byte, opts ReportOpts) ([]any, error) {
	m.deviceMu.Lock()
	defer m.deviceMu.Unlock()

	if err := m.validateROTs(); err != nil {
		return nil, err
	}

	if !opts.EnableRuntimeGPUAttestation {
		return nil, nil
	}

	var deviceReports []any
	var err error
	for _, deviceROT := range m.rots {
		if deviceROT.Vendor() == NvidiaGPU {
			deviceReport, e := deviceROT.Attest(nonce)
			if e != nil {
				err = errors.Join(err, e)
			} else {
				deviceReports = append(deviceReports, deviceReport)
			}
		}
	}
	return deviceReports, err
}

// MeasureDeviceEvidence collects attestation evidence from all attached ROTs, measures them into
// the event log via measurer, and transitions the devices to their ready states.
func (m *ROTManager) MeasureDeviceEvidence(nonce []byte, measurer EventMeasurer) error {
	m.deviceMu.Lock()
	defer m.deviceMu.Unlock()

	if err := m.validateROTs(); err != nil {
		return err
	}

	for _, rot := range m.rots {
		evidence, err := rot.Attest(nonce)
		if err != nil {
			return fmt.Errorf("failed to collect evidence for device %v: %w", rot.Vendor(), err)
		}

		pbEvidence, ok := evidence.(proto.Message)
		if !ok {
			return fmt.Errorf("unexpected evidence type %T from device %v", evidence, rot.Vendor())
		}

		evidenceBytes, err := proto.Marshal(pbEvidence)
		if err != nil {
			return fmt.Errorf("failed to marshal evidence from device %v: %w", rot.Vendor(), err)
		}

		var eventType cel.CosType
		switch rot.Vendor() {
		case NvidiaGPU:
			if _, ok := evidence.(*attestationpb.NvidiaAttestationReport); !ok {
				return fmt.Errorf("unexpected evidence type %T for Nvidia GPU", evidence)
			}
			eventType = cel.GPUDeviceAttestationBindingType
		default:
			return fmt.Errorf("unsupported vendor %v for event log measurement", rot.Vendor())
		}

		event := cel.CosTlv{
			EventType:    eventType,
			EventContent: evidenceBytes,
		}
		if measurer != nil {
			if err := measurer.MeasureEvent(event); err != nil {
				return fmt.Errorf("failed to measure attestation event for device %v: %w", rot.Vendor(), err)
			}
		}

		if enabler, ok := rot.(ReadyStateEnabler); ok {
			if err := enabler.EnableReadyState(); err != nil {
				return fmt.Errorf("failed to enable ready state for device %v: %w", rot.Vendor(), err)
			}
		}
	}
	return nil
}
