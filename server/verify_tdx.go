package server

import (
	tabi "github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tdx-guest/validate"
	tv "github.com/google/go-tdx-guest/verify"
)

// VerifyTdxOpts allows for customizing the functionality of VerifyAttestation's TDX verification.
type VerifyTdxOpts struct {
	Validation   *validate.Options
	Verification *tv.Options
}

// TdxDefaultValidateOpts returns a default validation policy for TDX attestation quote on GCE.
func TdxDefaultValidateOpts(tdxNonce []byte) *validate.Options {
	policy := &validate.Options{HeaderOptions: validate.HeaderOptions{},
		TdQuoteBodyOptions: validate.TdQuoteBodyOptions{}}
	policy.TdQuoteBodyOptions.ReportData = make([]byte, tabi.ReportDataSize)
	copy(policy.TdQuoteBodyOptions.ReportData, tdxNonce)
	return policy
}

// TdxDefaultOptions returns a default validation policy and verification options for TDX
// attestation quote on GCE.
func TdxDefaultOptions(tdxNonce []byte) *VerifyTdxOpts {
	return &VerifyTdxOpts{
		Validation:   TdxDefaultValidateOpts(tdxNonce),
		Verification: tv.DefaultOptions(),
	}
}

// VerifyTdxAttestation checks that the TDX attestation quote is valid. The TEE-specific attestation
// quote is extracted from the Attestation protobuf. At a granular level, this quote is fetched via
// go-tdx-guest's GetQuote client API.
// Supported quote formats - QuoteV4.
func VerifyTdxAttestation(tdxAttestationQuote any, opts *VerifyTdxOpts) error {
	// Check that the quote contains valid signature and certificates. Do not check revocations.
	if err := tv.TdxQuote(tdxAttestationQuote, opts.Verification); err != nil {
		return err
	}
	// Check that the fields of the quote are acceptable
	return validate.TdxQuote(tdxAttestationQuote, opts.Validation)
}
