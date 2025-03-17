package cmd

import (
	tabi "github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/validate"
	tv "github.com/google/go-tdx-guest/verify"
)

// verifyTdxOpts allows for customizing the functionality of VerifyAttestation's TDX verification.
type verifyTdxOpts struct {
	Validation   *validate.Options
	Verification *tv.Options
}

// tdxDefaultValidateOpts returns a default validation policy for TDX attestation quote on GCE.
func tdxDefaultValidateOpts(tdxNonce []byte) *validate.Options {
	policy := &validate.Options{HeaderOptions: validate.HeaderOptions{},
		TdQuoteBodyOptions: validate.TdQuoteBodyOptions{}}
	policy.TdQuoteBodyOptions.ReportData = make([]byte, tabi.ReportDataSize)
	copy(policy.TdQuoteBodyOptions.ReportData, tdxNonce)
	return policy
}

// verifyTdxAttestation checks that the TDX attestation quote is valid. The TEE-specific attestation
// quote is extracted from the Attestation protobuf. At a granular level, this quote is fetched via
// go-tdx-guest's GetQuote client API.
// Supported quote formats - QuoteV4.
func verifyTdxAttestation(tdxAttestationQuote any, opts *verifyTdxOpts) error {
	// Check that the quote contains valid signature and certificates. Do not check revocations.
	if err := tv.TdxQuote(tdxAttestationQuote, opts.Verification); err != nil {
		return err
	}
	// Check that the fields of the quote are acceptable
	return validate.TdxQuote(tdxAttestationQuote, opts.Validation)
}
