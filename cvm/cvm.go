package cvm

// CvmAttestation represents a standalone attestation over a challenge provided by the workload.
type CvmAttestation struct {
	Label []byte

	Challenge []byte

	Attestation *CvmAttestationQuote
}

// CvmAttestationQuote represents a quote from a Confidential VM.
type CvmAttestationQuote struct {
	// A TDX with CCEL and RTMR Attestation Quote.
	TdxAttestation *TdxCcelAttestation

	// Attestation reports for attached devices.
	DeviceReports []DeviceAttestationReport
}

type TdxCcelAttestation struct {
	// The CCEL event log. Formatted as described in the UEFI 2.10.
	// Contains events for guest OS boot.
	CcelData []byte

	// Formatted as a Canonical Event Log.
	// The event log containing Attested COS launcher events.
	CanonicalEventLog []byte

	// The TDX attestation quote.
	TdQuote []byte
}

// TODO: Define this.
type DeviceAttestationReport struct {
}
