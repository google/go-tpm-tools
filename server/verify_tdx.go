package server

import (
	tv "github.com/google/go-tdx-guest/verify"
)

// VerifyTdxOpts allows for customizing the functionality of VerifyAttestation's TDX verification.
type VerifyTdxOpts struct {
	Verification *tv.Options
}

// TdxDefaultOptions returns a default verification options for TDX
// attestation quote on GCE.
func TdxDefaultOptions() *VerifyTdxOpts {
	return &VerifyTdxOpts{
		Verification: tv.DefaultOptions(),
	}
}

// VerifyTdxAttestation checks that the TDX attestation quote is valid. The TEE-specific attestation
// quote is extracted from the Attestation protobuf. At a granular level, this quote is fetched via
// go-tdx-guest's GetQuote client API.
// Supported quote formats - QuoteV4.
func VerifyTdxAttestation(tdxAttestationQuote any, opts *VerifyTdxOpts) error {
	// Check that the quote contains valid signature and certificates. Do not check revocations.
	return tv.TdxQuote(tdxAttestationQuote, opts.Verification)
}
