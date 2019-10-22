package tpm2tools

import (
	"fmt"
	"io"

	"github.com/google/go-tpm-tools/proto"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// GetPCRCount asks the tpm how many PCRs it has.
func GetPCRCount(rw io.ReadWriter) (uint32, error) {
	props, _, err := tpm2.GetCapability(rw, tpm2.CapabilityTPMProperties, 1, uint32(tpm2.PCRCount))
	if err != nil {
		return 0, err
	}

	if len(props) != 1 {
		return 0, fmt.Errorf("tpm returned unexpected list of properties: %v", props)
	}

	return props[0].(tpm2.TaggedProperty).Value, nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// ReadPCRs fetchs the values of the specified PCRs for the specified hash.
func ReadPCRs(rw io.ReadWriter, pcrs []int, hash tpm2.Algorithm) (*proto.Pcrs, error) {
	pl := proto.Pcrs{
		Hash: proto.HashAlgo(hash),
		Pcrs: map[uint32][]byte{},
	}

	for i := 0; i < len(pcrs); i += 8 {
		end := min(i+8, len(pcrs))
		pcrSel := tpm2.PCRSelection{
			Hash: hash,
			PCRs: pcrs[i:end],
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

// ComputePCRSessionAuth calculates the auth value based on the given PCR proto
// and hash algorithm.
func ComputePCRSessionAuth(pcrs *proto.Pcrs, digestHash tpm2.Algorithm) ([]byte, error) {
	pcrDigest, err := ComputePCRDigest(pcrs, digestHash)
	if err != nil {
		return nil, err
	}
	getHash, err := digestHash.HashConstructor()
	if err != nil {
		return nil, err
	}

	summary := sessionSummary{
		OldDigest:      make([]byte, getHash().Size()),
		CmdIDPolicyPCR: uint32(tpm2.CmdPolicyPCR),
		NumPcrSels:     1,
		Sel:            computePCRSelection(pcrs),
		PcrDigest:      pcrDigest,
	}
	b, err := tpmutil.Pack(summary)
	if err != nil {
		return nil, fmt.Errorf("failed to pack for hashing: %v ", err)
	}

	hash := getHash()
	hash.Write(b)
	digest := hash.Sum(nil)
	return digest[:], nil
}

// ComputePCRDigest will take in a PCR proto and compute the digest based on the
// given PCR proto and hash algorithm.
func ComputePCRDigest(pcrs *proto.Pcrs, digestHash tpm2.Algorithm) ([]byte, error) {
	getHash, err := digestHash.HashConstructor()
	if err != nil {
		return nil, err
	}
	hash := getHash()
	for i := 0; i < 24; i++ {
		if pcrValue, exists := pcrs.Pcrs[uint32(i)]; exists {
			hash.Write(pcrValue)
		}
	}
	return hash.Sum(nil), nil
}

func computePCRSelection(pcrs *proto.Pcrs) tpmsPCRSelection {
	var pcrBits [3]byte
	for pcr := range pcrs.Pcrs {
		byteNum := pcr / 8
		bytePos := byte(1 << byte(pcr%8))
		pcrBits[byteNum] |= bytePos
	}
	return tpmsPCRSelection{
		Hash: tpm2.Algorithm(pcrs.Hash),
		Size: 3,
		PCRs: pcrBits[:],
	}
}
