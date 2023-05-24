package server

import (
	sabi "github.com/google/go-sev-guest/abi"
	spb "github.com/google/go-sev-guest/proto/sevsnp"
	"github.com/google/go-sev-guest/validate"
	sv "github.com/google/go-sev-guest/verify"
)

// The policy on GCE is to allow SMT, and eventually MigrateMA, but no debug bit.
var defaultSevSnpGuestPolicy = sabi.SnpPolicy{
	SMT:       true,
	MigrateMA: true,
}

// VerifySnpOpts allows for customizing the functionality of VerifyAttestation's SEV-SNP verification.
type VerifySnpOpts struct {
	Validation   *validate.Options
	Verification *sv.Options
}

// SevSnpDefaultValidateOpts returns a default validation policy for SEV-SNP attestation reports on GCE.
func SevSnpDefaultValidateOpts(tpmNonce []byte) *validate.Options {
	policy := &validate.Options{GuestPolicy: defaultSevSnpGuestPolicy}
	policy.ReportData = make([]byte, sabi.ReportDataSize)
	copy(policy.ReportData, tpmNonce)
	return policy
}

// SevSnpDefaultValidateOptsForTest is a non-production policy only meant for testing. It is more
// permissive in the kinds of reports it validates, including whether the host is allowed to
// forcibly decrypt data (for debugging purposes).
func SevSnpDefaultValidateOptsForTest(tpmNonce []byte) *validate.Options {
	policy := SevSnpDefaultValidateOpts(tpmNonce)
	policy.GuestPolicy.Debug = true
	return policy
}

// SevSnpDefaultOptions returns a default validation policy and verification options for SEV-SNP
// attestation reports on GCE.
func SevSnpDefaultOptions(tpmNonce []byte) *VerifySnpOpts {
	return &VerifySnpOpts{
		Validation:   SevSnpDefaultValidateOpts(tpmNonce),
		Verification: sv.DefaultOptions(),
	}
}

// VerifySevSnpAttestation checks that the SEV-SNP attestation report matches expectations for the
// product.
func VerifySevSnpAttestation(attestation *spb.Attestation, opts *VerifySnpOpts) error {
	// Check that the report is signed by a valid AMD key. Do not check revocations. This must be
	// done before validation to ensure the certificates are filled in by the verify library.
	if err := sv.SnpAttestation(attestation, opts.Verification); err != nil {
		return err
	}
	// Check that the fields of the report are acceptable.
	return validate.SnpAttestation(attestation, opts.Validation)
}
