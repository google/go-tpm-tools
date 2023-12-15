package server

import (
	tabi "github.com/google/go-tdx-guest/abi"
	tpb "github.com/google/go-tdx-guest/proto/tdx"
	"github.com/google/go-tdx-guest/validate"
	tv "github.com/google/go-tdx-guest/verify"
)

// VerifyTdxOpts allows for customizing the functionality of VerifyAttestation's TDX verification.
type VerifyTdxOpts struct {
	Validation   *validate.Options
	Verification *tv.Options
}

// TdxDefaultValidateOpts returns a default validation policy for TDX attestation quote on GCE.
func TdxDefaultValidateOpts(tpmNonce []byte) *validate.Options {
	policy := &validate.Options{HeaderOptions: validate.HeaderOptions{},
		TdQuoteBodyOptions: validate.TdQuoteBodyOptions{}}
	policy.TdQuoteBodyOptions.ReportData = make([]byte, tabi.ReportDataSize)
	copy(policy.TdQuoteBodyOptions.ReportData, tpmNonce)
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

// VerifyTdxAttestation checks that the TDX attestation quote is valid
func VerifyTdxAttestation(attestation *tpb.QuoteV4, opts *VerifyTdxOpts) error {
	// Check that the quote contains valid signature and certificates. Do not check revocations.
	if err := tv.TdxQuote(attestation, opts.Verification); err != nil {
		return err
	}

	// Check that the fields of the quote are acceptable
	return validate.TdxQuote(attestation, opts.Validation)
}
