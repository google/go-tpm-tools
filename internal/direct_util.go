// Package internal contains private helper functions needed in client and server
package internal

import (
	"fmt"

	"github.com/google/go-tpm/tpmutil"

	"github.com/google/go-tpm/direct/structures/tpm"
	"github.com/google/go-tpm/direct/structures/tpml"
	"github.com/google/go-tpm/direct/structures/tpms"
)

// CreateTPMSPCRSelection will create a TPMS PCR Selection given a slice of uint32 and a tpm.AlgID.
// This function only supports up to 24 PCRs.
func CreateTPMSPCRSelection(s []uint32, hash tpm.AlgID) (tpms.PCRSelection, error) {
	const sizeOfPCRSelect = 3

	PCRs := make(tpmutil.RawBytes, sizeOfPCRSelect)

	for _, n := range s {
		if n >= 8*sizeOfPCRSelect {
			return tpms.PCRSelection{}, fmt.Errorf("PCR index %d is out of range (exceeds maximum value %d)", n, 8*sizeOfPCRSelect-1)
		}
		byteNum := n / 8
		bytePos := byte(1 << (n % 8))
		PCRs[byteNum] |= bytePos
	}

	return tpms.PCRSelection{
		Hash:      hash,
		PCRSelect: PCRs,
	}, nil
}

// CreateTPMLPCRSelection will create a TPMS PCR Selection given a slice of uint32 and a tpm.AlgID
// Similar to createTPMSPCRSelection this function only supports up to 24 PCRS.
func CreateTPMLPCRSelection(s []uint32, hash tpm.AlgID) (tpml.PCRSelection, error) {
	tpmsSel, err := CreateTPMSPCRSelection(s, hash)
	if err != nil {
		return tpml.PCRSelection{}, fmt.Errorf("failed to create PCRSelection: %v", err)
	}
	return tpml.PCRSelection{PCRSelections: []tpms.PCRSelection{tpmsSel}}, nil
}
