package cmd

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

// verifySnpOpts allows for customizing the functionality of VerifyAttestation's SEV-SNP verification.
type verifySnpOpts struct {
	Validation   *validate.Options
	Verification *sv.Options
}

// sevSnpDefaultValidateOpts returns a default validation policy for SEV-SNP attestation reports on GCE.
func sevSnpDefaultValidateOpts(tpmNonce []byte) *validate.Options {
	policy := &validate.Options{GuestPolicy: defaultSevSnpGuestPolicy}
	policy.ReportData = make([]byte, sabi.ReportDataSize)
	copy(policy.ReportData, tpmNonce)
	return policy
}

// verifySevSnpAttestation checks that the SEV-SNP attestation report matches expectations for the
// product.
func verifySevSnpAttestation(attestation *spb.Attestation, opts *verifySnpOpts) error {
	// Check that the report is signed by a valid AMD key. Do not check revocations. This must be
	// done before validation to ensure the certificates are filled in by the verify library.
	if err := sv.SnpAttestation(attestation, opts.Verification); err != nil {
		return err
	}
	// Check that the fields of the report are acceptable.
	return validate.SnpAttestation(attestation, opts.Validation)
}
