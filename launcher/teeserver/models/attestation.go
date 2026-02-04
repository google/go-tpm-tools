// Package models contains structs for Confidential VM attestation.
package models

import (
	attestpb "github.com/google/go-tpm-tools/proto/attest"
)

const (
	// WorkloadAttestationLabel is the label used by Confidential Space.
	WorkloadAttestationLabel = "WORKLOAD_ATTESTATION"
)

// VMAttestation represents a standalone attestation over a challenge provided by the workload.
type VMAttestation struct {
	// Label provided by the attesting entity. For Confidential Space, this shall be "WORKLOAD_ATTESTATION".
	Label []byte `json:"label"`

	// Challenge provided by the workload.
	Challenge []byte `json:"challenge"`

	// Optional, provided by WSD.
	ExtraData []byte `json:"extra_data,omitempty"`

	// Quote from the CVM.
	Quote *VMAttestationQuote `json:"vm_attestation_quote"`

	// Attestation reports for attached devices.
	DeviceReports []DeviceAttestationReport `json:"device_reports,omitempty"`
}

// VMAttestationQuote represents a quote from a Confidential VM.
type VMAttestationQuote struct {
	// A TDX with CCEL and RTMR Attestation Quote.
	TDXCCELQuote *TDXCCELQuote `json:"tdx_ccel_quote,omitempty"`

	// A vTPM Attestation Quote.
	// TODO: Fork the definition of attestpb.Attestation to here.
	VTPMAttestation *attestpb.Attestation `json:"vtpm_attestation,omitempty"`
}

// TDXCCELQuote represents a TDX attestation with CCEL event logs.
type TDXCCELQuote struct {
	// The CCEL event log. Formatted as described in the UEFI 2.10.
	// Contains events for guest OS boot.
	CCELBootEventLog []byte `json:"ccel_boot_event_log"`

	// Formatted as a Canonical Event Log.
	// The event log containing Attested COS launcher events.
	CELLaunchEventLog []byte `json:"cel_launch_event_log"`

	// The TDX attestation quote.
	TDQuote []byte `json:"td_quote"`
}

// DeviceAttestationReport represents an attestation report from a device.
// TODO: Define this.
type DeviceAttestationReport struct {
}
