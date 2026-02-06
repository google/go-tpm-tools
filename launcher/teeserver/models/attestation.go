// Package models contains structs for Confidential VM attestation.
package models

import (
	attestpb "github.com/google/go-tpm-tools/proto/attest"
)

// CVMAttestation represents a standalone attestation over a challenge provided by the workload.
type CVMAttestation struct {
	// Label provided by the attesting entity. For Confidential Space, this shall be "WORKLOAD_ATTESTATION".
	Label []byte `json:"label"`

	// Challenge provided by the workload.
	Challenge []byte `json:"challenge"`

	// Attestation from the CVM.
	Attestation *CVMAttestationQuote `json:"cvm_attestation_quote"`
}

// CVMAttestationQuote represents a quote from a Confidential VM.
type CVMAttestationQuote struct {
	// A TDX with CCEL and RTMR Attestation Quote.
	TDXAttestation *TDXCCELAttestation `json:"tdx_ccel_attestation,omitempty"`

	// A TPM Attestation Quote.
	TPMAttestation *attestpb.Attestation `json:"tpm_attestation,omitempty"`

	// Attestation reports for attached devices.
	DeviceReports []DeviceAttestationReport `json:"device_attestation_reports,omitempty"`
}

// TDXCCELAttestation represents a TDX attestation with CCEL event logs.
type TDXCCELAttestation struct {
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
