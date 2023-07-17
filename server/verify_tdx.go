package server

import (
	tpb "github.com/google/go-tdx-guest/proto/tdx"

	tv "github.com/google/go-tdx-guest/verify"
)

// VerifyTdxOpts allows for customizing the functionality of VerifyAttestation's TDX verification.
type VerifyTdxOpts struct {
	Verification *tv.Options
}

// TdxDefaultOptions returns a default verification options for TDX
// attestation reports on GCE.
func TdxDefaultOptions(tpmNonce []byte) *VerifyTdxOpts {
	return &VerifyTdxOpts{
		Verification: tv.DefaultOptions(),
	}
}

// VerifySevSnpAttestation checks that the SEV-SNP attestation report matches expectations for the
// product.
func VerifyTdxAttestation(attestation *tpb.QuoteV4, opts *VerifyTdxOpts) error {
	// Check that the quote contains valid signature and certificates. Do not check revocations.
	return tv.TdxVerify(attestation, opts.Verification)
}
