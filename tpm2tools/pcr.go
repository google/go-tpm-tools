package tpm2tools

import (
	"fmt"
	"io"
	"crypto/sha256"
	"crypto"

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

// ComputePCRSessionAuth calculates the auth value using the specified hash version of the provided PCRs.
func ComputePCRSessionAuth(pcrProto proto.Pcrs) ([]byte, error) {
	var pcrHash tpm2.Algorithm
	switch pcrProto.Hash {
	case proto.HashAlgo_SHA1:
		pcrHash = tpm2.AlgSHA1
	case proto.HashAlgo_SHA256:
		pcrHash = tpm2.AlgSHA256
	default:
		return nil, fmt.Errorf("Invalid hash alg: %v", pcrProto.Hash)
	}

	var pcrBits [3]byte
	for pcr := range pcrProto.Pcrs {
		byteNum := pcr / 8
		bytePos := byte(1 << byte(pcr%8))
		pcrBits[byteNum] |= bytePos
	}
	pcrDigest := digestPCRList(pcrProto.Pcrs)

	summary := sessionSummary{
		OldDigest:      make([]byte, sha256.Size),
		CmdIDPolicyPCR: uint32(tpm2.CmdPolicyPCR),
		NumPcrSels:     1,
		Sel: tpmsPCRSelection{
			Hash: pcrHash,
			Size: 3,
			PCRs: pcrBits[:],
		},
		PcrDigest: pcrDigest,
	}
	b, err := tpmutil.Pack(summary)
	if err != nil {
		return nil, fmt.Errorf("failed to pack for hashing: %v ", err)
	}

	digest := sha256.Sum256(b)
	return digest[:], nil
}

func digestPCRList(pcrs map[uint32][]byte) []byte {
	hash := crypto.SHA256.New()
	for i := 0; i < 24; i++ {
		if pcrValue, exists := pcrs[uint32(i)]; exists {
			hash.Write(pcrValue)
		}
	}
	return hash.Sum(nil)
}
