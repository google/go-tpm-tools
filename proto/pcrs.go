// Package proto contains protocol buffers that are exchanged between the client
// and server. Note, some of these types have additional helper methods.
package proto

import (
	"bytes"
	"crypto"
	"fmt"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// CheckIfSubsetOf verifies if the pcrs PCRs are a valid "subset" of the provided
// "superset" of PCRs. The PCR values must match (if present), and all PCRs must
// be present in the superset. This function will return an error containing the
// first missing or mismatched PCR number.
func (pcrs *Pcrs) CheckIfSubsetOf(superset *Pcrs) error {
	if pcrs.GetHash() != superset.GetHash() {
		return fmt.Errorf("PCR hash algo not matching: %v, %v", pcrs.GetHash(), superset.GetHash())
	}
	for pcrNum, pcrVal := range pcrs.GetPcrs() {
		if expectedVal, ok := superset.GetPcrs()[pcrNum]; ok {
			if !bytes.Equal(expectedVal, pcrVal) {
				return fmt.Errorf("PCR %d mismatch: expected %v, got %v", pcrNum, expectedVal, pcrVal)
			}
		} else {
			return fmt.Errorf("PCR %d mismatch: value missing from the superset PCRs", pcrNum)
		}
	}
	return nil
}

// PCRSelection returns the corresponding tpm2.PCRSelection for the PCR data.
func (pcrs *Pcrs) PCRSelection() tpm2.PCRSelection {
	sel := tpm2.PCRSelection{Hash: tpm2.Algorithm(pcrs.GetHash())}

	for pcrNum := range pcrs.GetPcrs() {
		sel.PCRs = append(sel.PCRs, int(pcrNum))
	}
	return sel
}

// HasSamePCRSelection checks if the Pcrs has the same PCRSelection as the
// provided given tpm2.PCRSelection (including the hash algorithm).
func (pcrs *Pcrs) HasSamePCRSelection(pcrSel tpm2.PCRSelection) bool {
	if tpm2.Algorithm(pcrs.Hash) != pcrSel.Hash {
		return false
	}
	if len(pcrs.GetPcrs()) != len(pcrSel.PCRs) {
		return false
	}
	for _, p := range pcrSel.PCRs {
		if _, ok := pcrs.Pcrs[uint32(p)]; !ok {
			return false
		}
	}
	return true
}

// ComputePCRSessionAuth calculates the authorization value for the given PCRs.
func (pcrs *Pcrs) ComputePCRSessionAuth(hashAlg crypto.Hash) []byte {
	// Start with all zeros, we only use a single policy command on our session.
	oldDigest := make([]byte, hashAlg.Size())
	ccPolicyPCR, _ := tpmutil.Pack(tpm2.CmdPolicyPCR)

	// Extend the policy digest, see TPM2_PolicyPCR in Part 3 of the spec.
	hash := hashAlg.New()
	hash.Write(oldDigest)
	hash.Write(ccPolicyPCR)
	hash.Write(encodePCRSelection(pcrs.PCRSelection()))
	hash.Write(pcrs.ComputePCRDigest(hashAlg))
	newDigest := hash.Sum(nil)
	return newDigest[:]
}

// ComputePCRDigest computes the digest of the Pcrs. Note that the digest hash
// algorithm may differ from the PCRs' hash (which denotes the PCR bank).
func (pcrs *Pcrs) ComputePCRDigest(hashAlg crypto.Hash) []byte {
	hash := hashAlg.New()
	for i := 0; i < 24; i++ {
		if pcrValue, exists := pcrs.Pcrs[uint32(i)]; exists {
			hash.Write(pcrValue)
		}
	}
	return hash.Sum(nil)
}

// Encode a tpm2.PCRSelection as if it were a TPML_PCR_SELECTION
func encodePCRSelection(sel tpm2.PCRSelection) []byte {
	// Encode count, pcrSelections.hash and pcrSelections.sizeofSelect fields
	buf, _ := tpmutil.Pack(uint32(1), sel.Hash, byte(3))
	// Encode pcrSelect bitmask
	pcrBits := make([]byte, 3)
	for _, pcr := range sel.PCRs {
		byteNum := pcr / 8
		bytePos := 1 << uint(pcr%8)
		pcrBits[byteNum] |= byte(bytePos)
	}

	return append(buf, pcrBits...)
}
