package tpm2tools

import (
	"fmt"
	"hash"
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

// ComputePCRSessionAuth calculates the auth value using the SHA256 versions of the provided PCRs.
func ComputePCRSessionAuth(pcrProto proto.Pcrs) ([]byte, error) {
	pcrs := map[int][]byte{}
	for p, v := range pcrProto.Pcrs {
		pcrs[int(p)] = v
	}
	pcrAlg, err := getHashAlg(pcrProto.Hash)
	if err != nil {
		return nil, err
	}
	getHash, err := pcrAlg.HashConstructor()
	if err != nil {
		return nil, err
	}
	var pcrBits [3]byte
	for pcr := range pcrs {
		byteNum := pcr / 8
		bytePos := byte(1 << byte(pcr%8))
		pcrBits[byteNum] |= bytePos
	}
	pcrDigest := digestPCRList(pcrs, getHash())

	summary := sessionSummary{
		OldDigest:      make([]byte, getHash().Size()),
		CmdIDPolicyPCR: uint32(tpm2.CmdPolicyPCR),
		NumPcrSels:     1,
		Sel: tpmsPCRSelection{
			Hash: pcrAlg,
			Size: 3,
			PCRs: pcrBits[:],
		},
		PcrDigest: pcrDigest,
	}
	b, err := tpmutil.Pack(summary)
	if err != nil {
		return nil, fmt.Errorf("failed to pack for hashing: %v ", err)
	}
	digestHash := getHash()
	digestHash.Write(b)
	digest := digestHash.Sum(nil)

	return digest[:], nil
}

func digestPCRList(pcrs map[int][]byte, hash hash.Hash) []byte {
	for i := 0; i < 24; i++ {
		if pcrValue, exists := pcrs[i]; exists {
			hash.Write(pcrValue)
		}
	}
	return hash.Sum(nil)
}

func getHashAlg(alg proto.HashAlgo) (tpm2.Algorithm, error) {
	switch alg {
	case proto.HashAlgo_SHA1:
		return tpm2.AlgSHA1, nil
	case proto.HashAlgo_SHA256:
		return tpm2.AlgSHA256, nil
	default:
		return tpm2.AlgNull, fmt.Errorf("Invalid hash alg: %v", alg)
	}
}
