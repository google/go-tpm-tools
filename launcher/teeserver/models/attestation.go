// Package models contains structs for Confidential VM attestation.
package models

const (
	// WorkloadAttestationLabel is the label used by Confidential Space.
	WorkloadAttestationLabel = "WORKLOAD_ATTESTATION"
)

// GPUArchitectureType enums are represented as integers with a custom type
type GPUArchitectureType int32

// The following values are based on NVIDIA's GPU architecture generations.
const (
	GpuArchitectureUnspecified GPUArchitectureType = iota // Unspecified architecture.
	GpuArchitectureKepler      GPUArchitectureType = 1    // Kepler architecture.
	GpuArchitectureMaxwell     GPUArchitectureType = 2    // Maxwell architecture.
	GpuArchitecturePascal      GPUArchitectureType = 3    // Pascal architecture.
	GpuArchitectureVolta       GPUArchitectureType = 4    // Volta architecture.
	GpuArchitectureTuring      GPUArchitectureType = 5    // Turing architecture.
	GpuArchitectureAmpere      GPUArchitectureType = 6    // Ampere architecture.
	GpuArchitectureAda         GPUArchitectureType = 7    // Ada architecture.
	GpuArchitectureHopper      GPUArchitectureType = 8    // Hopper architecture.
	GpuArchitectureUnsupported GPUArchitectureType = 9    // Unknown architecture.
	GpuArchitectureBlackwell   GPUArchitectureType = 10   // Blackwell architecture.
)

// String returns the string representation of a GPUArchitectureType based upon value.
func (g GPUArchitectureType) String() string {
	switch g {
	case GpuArchitectureKepler:
		return "GPU_ARCHITECTURE_KEPLER"
	case GpuArchitectureBlackwell:
		return "GPU_ARCHITECTURE_BLACKWELL"
	case GpuArchitectureUnspecified:
		return "GPU_ARCHITECTURE_UNSPECIFIED"
	default:
		return "GPU_ARCHITECTURE_UNSUPPORTED"
	}
}

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

	// TPMQuote represents the standalone vTPM Attestation Quote.
	TPMQuote *TPMQuote `json:"tpm_quote,omitempty"`
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
type DeviceAttestationReport struct {
	NvidiaReport *NvidiaAttestationReport `json:"nvidia_report,omitempty"`
}

// NvidiaAttestationReport represents the attestation report for NVIDIA GPUs, which may include SPT or MPT reports.
type NvidiaAttestationReport struct {
	Spt *SinglePassthroughAttestation         `json:"spt,omitempty"` // Single GPU Passthrough (SPT) attestation report
	Mpt *MultiGpuSecurePassthroughAttestation `json:"mpt,omitempty"` //  Multiple GPU Passthrough (MPT) attestation report
}

// SinglePassthroughAttestation is a placeholder for the 'spt' field.
type SinglePassthroughAttestation struct {
	GPUQuote GPUInfo `json:"gpu_quote"`
}

// MultiGpuSecurePassthroughAttestation contains the actual GPU quotes.
type MultiGpuSecurePassthroughAttestation struct {
	GPUQuotes []GPUInfo `json:"gpu_quotes"`
}

// TPMAttestationEndorsement represents the endorsement of a TPM attestation.
type TPMAttestationEndorsement struct {
	AKCertEndorsement *AKCertEndorsement `json:"ak_cert_endorsement,omitempty"`
	TitanEndorsement  *TitanEndorsement  `json:"titan_endorsement,omitempty"`
}

// AKCertEndorsement represents an attestation key (AK) certificate and cert chain.
type AKCertEndorsement struct {
	AKCert      []byte   `json:"ak_cert"`
	AKCertChain [][]byte `json:"ak_cert_chain"`
}

// TitanEndorsement represents the endorsement of a Titan chip.
type TitanEndorsement struct {
	// Certificate signed by Titan's DICE alias key over the EK used to generate the
	// quotes. On Titan, the EK is a signing key that can be used directly.
	EKCert []byte `json:"ek_cert"`

	// Certificate signed by Titan's DeviceID public key over the alias key used to
	// endorse the EK.
	AliasCert []byte `json:"alias_cert"`

	// Device ID certificate for the Titan chip.
	DeviceIDCert []byte `json:"device_id_cert"`
}

// TPMQuote represents a TPM Quote.
type TPMQuote struct {
	// Generated by calling TPM2_Quote on each PCR bank.
	Quotes []*SignedQuote `json:"quotes"`

	// The binary TCG Event Log containing events measured into the TPM by the
	// platform firmware and operating system. Formatted as described in the
	// "TCG PC Client Platform Firmware Profile Specification" as a series of
	// TCG_PCR_EVENT2 entries.
	PCClientBootEventLog []byte `json:"pcclient_boot_event_log"`

	// Formatted as a Canonical Event Log.
	// The event log containing Attested COS launcher events.
	CELLaunchEventLog []byte `json:"cel_launch_event_log"`

	// Endorsement for the TPM attestation.
	Endorsement *TPMAttestationEndorsement `json:"endorsement"`
}

// SignedQuote represents a signed TPM quote.
type SignedQuote struct {
	HashAlgorithm uint32            `json:"hash_algorithm"` // Encoded as a TPM_ALG_ID.
	PCRValues     map[uint32][]byte `json:"pcr_values"`     // Raw binary values of each PCR being quoted.
	TPMSAttest    []byte            `json:"tpms_attest"`    // Contains a TPMS_QUOTE_INFO.
	TPMTSignature []byte            `json:"tpmt_signature"` // Contains the signature.
}

// GPUInfo contains the specific hardware identity and evidence for a single GPU.
type GPUInfo struct {
	UUID                        string `json:"uuid"`                          // The UUID of the GPU device.
	DriverVersion               string `json:"driver_version"`                // The driver version of the GPU.
	VBIOSVersion                string `json:"vbios_version"`                 // The VBIOS version of the GPU.
	GPUArchitectureType         string `json:"gpu_architecture_type"`         // The architecture type of the GPU.
	AttestationCertificateChain []byte `json:"attestation_certificate_chain"` // The raw certificate chain for attestation.
	AttestationReport           []byte `json:"attestation_report"`            // The raw attestation report for the GPU.
}
