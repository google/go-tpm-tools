// Package models contains structs for Confidential VM attestation.
package models

import (
	"github.com/google/go-tpm-tools/proto/tpm"
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

	// VTPMAttestation represents the standalone vTPM Attestation Quote.
	VTPMAttestation *VTPMAttestation `json:"vtpm_attestation,omitempty"`
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

// VTPMAttestation represents a vTPM attestation quote.
type VTPMAttestation struct {
	// Attestation Key (AK) Public Area, encoded as a TPMT_PUBLIC
	AkPub []byte `json:"ak_pub,omitempty"`

	// Quotes over all supported PCR banks
	Quotes []*tpm.Quote `json:"quotes,omitempty"`

	// TCG PC Client Boot Event Log, encoded in the raw binary format.
	// Can be SHA-1 or crypto-agile.
	PCClientBootEventLog []byte `json:"pcclient_boot_event_log"`

	// Formatted as a Canonical Event Log.
	// The event log containing Attested COS launcher events.
	CELLaunchEventLog []byte `json:"cel_launch_event_log"`

	// Attestation Key (AK) Certificate, encoded as ASN.1 DER.
	// Optional.
	AkCert []byte `json:"ak_cert,omitempty"`

	// Intermediate Certificates for verifying the AK Certificate, encoded as
	// ASN.1 DER. Optional.
	IntermediateCerts [][]byte `json:"intermediate_certs,omitempty"`
}
