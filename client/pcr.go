package client

import (
	"crypto"
	"fmt"
	"io"
	"math"

	tpmpb "github.com/google/go-tpm-tools/proto"
	"github.com/google/go-tpm/tpm2"
)

// NumPCRs is set to the spec minimum of 24, as that's all go-tpm supports.
const NumPCRs = 24

// We hard-code SHA256 as the policy session hash algorithms. Note that this
// differs from the PCR hash algorithm (which selects the bank of PCRs to use)
// and the Public area Name algorithm. We also chose this for compatibility with
// github.com/google/go-tpm/tpm2, as it hardcodes the nameAlg as SHA256 in
// several places. Two constants are used to avoid repeated conversions.
const (
	SessionHashAlg    = crypto.SHA256
	SessionHashAlgTpm = tpm2.AlgSHA256
)

// CertifyHashAlgTpm is the hard-coded algorithm used in certify PCRs.
const CertifyHashAlgTpm = tpm2.AlgSHA256

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ReadPCRs fetches all the PCR values specified in sel, making multiple calls
// to the TPM if necessary.
func ReadPCRs(rw io.ReadWriter, sel tpm2.PCRSelection) (*tpmpb.Pcrs, error) {
	pl := tpmpb.Pcrs{
		Hash: tpmpb.HashAlgo(sel.Hash),
		Pcrs: map[uint32][]byte{},
	}

	for i := 0; i < len(sel.PCRs); i += 8 {
		end := min(i+8, len(sel.PCRs))
		pcrSel := tpm2.PCRSelection{
			Hash: sel.Hash,
			PCRs: sel.PCRs[i:end],
		}

		pcrMap, err := tpm2.ReadPCRs(rw, pcrSel)
		if err != nil {
			return nil, err
		}

		for pcr, val := range pcrMap {
			pl.Pcrs[uint32(pcr)] = val
		}
	}

	return &pl, nil
}

// ReadAllPCRs fetches all the PCR values from all implemented PCR banks.
func ReadAllPCRs(rw io.ReadWriter) ([]*tpmpb.Pcrs, error) {
	sels, moreData, err := tpm2.GetCapability(rw, tpm2.CapabilityPCRs, math.MaxUint32, 0)
	if err != nil {
		return nil, fmt.Errorf("listing implemented PCR banks: %w", err)
	}
	if moreData {
		return nil, fmt.Errorf("extra data from GetCapability")
	}
	allPcrs := make([]*tpmpb.Pcrs, len(sels))
	for i, sel := range sels {
		sel, ok := sel.(tpm2.PCRSelection)
		if !ok {
			return nil, fmt.Errorf("unexpected data from GetCapability")
		}
		allPcrs[i], err = ReadPCRs(rw, sel)
		if err != nil {
			return nil, fmt.Errorf("reading bank %x PCRs: %w", sel.Hash, err)
		}
	}
	return allPcrs, nil
}

// SealCurrent seals data to the current specified PCR selection.
type SealCurrent struct{ tpm2.PCRSelection }

// SealTarget predicatively seals data to the given specified PCR values.
type SealTarget struct{ Pcrs *tpmpb.Pcrs }

// SealOpt specifies the PCR values that should be used for Seal().
type SealOpt interface {
	PCRsForSealing(rw io.ReadWriter) (*tpmpb.Pcrs, error)
}

// PCRsForSealing read from TPM and return the selected PCRs.
func (p SealCurrent) PCRsForSealing(rw io.ReadWriter) (*tpmpb.Pcrs, error) {
	if len(p.PCRSelection.PCRs) == 0 {
		panic("SealCurrent contains 0 PCRs")
	}
	return ReadPCRs(rw, p.PCRSelection)
}

// PCRsForSealing return the target PCRs.
func (p SealTarget) PCRsForSealing(_ io.ReadWriter) (*tpmpb.Pcrs, error) {
	if len(p.Pcrs.GetPcrs()) == 0 {
		panic("SealTaget contains 0 PCRs")
	}
	return p.Pcrs, nil
}

// CertifyCurrent certifies that a selection of current PCRs have the same value when sealing.
// Hash Algorithm in the selection should be CertifyHashAlgTpm.
type CertifyCurrent struct{ tpm2.PCRSelection }

// CertifyExpected certifies that the TPM had a specific set of PCR values when sealing.
// Hash Algorithm in the PCR proto should be CertifyHashAlgTpm.
type CertifyExpected struct{ Pcrs *tpmpb.Pcrs }

// CertifyOpt determines if the given PCR value can pass certification in Unseal().
type CertifyOpt interface {
	CertifyPCRs(rw io.ReadWriter, certified *tpmpb.Pcrs) error
}

// CertifyPCRs from CurrentPCRs will read PCR values from TPM and compare the digest.
func (p CertifyCurrent) CertifyPCRs(rw io.ReadWriter, pcrs *tpmpb.Pcrs) error {
	if len(p.PCRSelection.PCRs) == 0 {
		panic("CertifyCurrent contains 0 PCRs")
	}
	current, err := ReadPCRs(rw, p.PCRSelection)
	if err != nil {
		return err
	}
	return current.CheckIfSubsetOf(pcrs)
}

// CertifyPCRs will compare the digest with given expected PCRs values.
func (p CertifyExpected) CertifyPCRs(_ io.ReadWriter, pcrs *tpmpb.Pcrs) error {
	if len(p.Pcrs.GetPcrs()) == 0 {
		panic("CertifyExpected contains 0 PCRs")
	}
	return p.Pcrs.CheckIfSubsetOf(pcrs)
}

// FullPcrSel will return a full PCR selection based on the total PCR number
// of the TPM with the given hash algo.
func FullPcrSel(hash tpm2.Algorithm) tpm2.PCRSelection {
	sel := tpm2.PCRSelection{Hash: hash}
	for i := 0; i < NumPCRs; i++ {
		sel.PCRs = append(sel.PCRs, int(i))
	}
	return sel
}
