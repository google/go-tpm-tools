package server

import (
	sabi "github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/validate"
	sv "github.com/google/go-sev-guest/verify"
)

// VerifySnpOpts allows for customizing the functionality of VerifyAttestation's SEV-SNP verification.
type VerifySnpOpts struct {
	// ReportData is the expected REPORT_DATA field of the attestation report.
	ReportData [sabi.ReportDataSize]byte
	// TrustedRoots defines which AMD root (ARK) and intermediate (ASK) keys to trust
	// to verify a versioned chip endorsement key (VCEK) that signs attestation reports.
	// If nil, falls back on go-sev-guest's embedded root certs. Maps a product name
	// to an array of allowed roots.
	TrustedRoots map[string][]*sv.AMDRootCerts
	// Allow the debug bit to be set (should only be used for testing).
	AllowDebugTestOnly bool
}

// VerifySevSnpAttestation checks that the SEV-SNP attestation report matches expectations for the
// product.
func VerifySevSnpAttestation(attestation *spb.Attestation, opts *VerifySnpOpts) error {
	// Check that the fields of the report are acceptable.
	if err := validate.SnpAttestation(attestation, &validate.Options{
		ReportData:  opts.ReportData[:],
		GuestPolicy: sabi.SnpPolicy{Debug: opts.AllowDebugTestOnly},
	}); err != nil {
		return err
	}
	// Check that the report is signed by a valid AMD key. Do not check revocations.
	return sv.SnpAttestation(attestation, &sv.Options{TrustedRoots: opts.TrustedRoots})
}
