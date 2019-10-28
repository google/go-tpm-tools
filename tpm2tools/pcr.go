package tpm2tools

import (
	"crypto"
	"fmt"
	"io"

	"github.com/google/go-tpm-tools/proto"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	// sessionHashAlg is the hash algorithm used to compute the policy digest. If
	// the policy digest is used as the authPolicy for an object, sessionHashAlg
	// should match the objects name alg. For compatibility with
	// github.com/google/go-tpm/tpm2, we use SHA256, as tpm2 hardcodes the
	// nameAlg as SHA256 in several places.
	// Both crypto and tpm2 consts are set to avoid the need for conversion.
	sessionHashAlg    = crypto.SHA256
	sessionHashAlgTpm = tpm2.AlgSHA256
)

type tpmsPCRSelection struct {
	Hash tpm2.Algorithm
	Size byte
	PCRs tpmutil.RawBytes
}

type sessionSummary struct {
	OldDigest      tpmutil.RawBytes
	CmdIDPolicyPCR uint32
	NumPcrSels     uint32
	Sel            tpmsPCRSelection
	PcrDigest      tpmutil.RawBytes
}

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
func ComputePCRSessionAuth(pcrs *proto.Pcrs) ([]byte, error) {
	pcrDigest := ComputePCRDigest(pcrs)

	summary := sessionSummary{
		OldDigest:      make([]byte, sessionHashAlg.Size()),
		CmdIDPolicyPCR: uint32(tpm2.CmdPolicyPCR),
		NumPcrSels:     1,
		Sel:            computePCRSelection(pcrs),
		PcrDigest:      pcrDigest,
	}
	b, err := tpmutil.Pack(summary)
	if err != nil {
		return nil, fmt.Errorf("failed to pack for hashing: %v ", err)
	}

	hash := sessionHashAlg.New()
	hash.Write(b)
	digest := hash.Sum(nil)
	return digest[:], nil
}

// ComputePCRDigest will take in a PCR proto and compute the digest based on the
// given PCR proto.
func ComputePCRDigest(pcrs *proto.Pcrs) []byte {
	hash := sessionHashAlg.New()
	for i := 0; i < 24; i++ {
		if pcrValue, exists := pcrs.Pcrs[uint32(i)]; exists {
			hash.Write(pcrValue)
		}
	}
	return hash.Sum(nil)
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

func getPCRSessionAuth(rw io.ReadWriter, pcrs []int, pcrHash tpm2.Algorithm) ([]byte, error) {
	handle, err := createPCRSession(rw, pcrs, pcrHash)
	if err != nil {
		return nil, fmt.Errorf("failed to get digest: %v", err)
	}
	defer tpm2.FlushContext(rw, handle)

	digest, err := tpm2.PolicyGetDigest(rw, handle)
	if err != nil {
		return nil, fmt.Errorf("could not get digest from session: %v", err)
	}

	return digest, nil
}

func createPCRSession(rw io.ReadWriter, pcrs []int, pcrHash tpm2.Algorithm) (tpmutil.Handle, error) {
	nonceIn := make([]byte, 16)
	/* This session assumes the bus is trusted.  */
	handle, _, err := tpm2.StartAuthSession(
		rw,
		tpm2.HandleNull,
		tpm2.HandleNull,
		nonceIn,
		/*secret=*/ nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		sessionHashAlgTpm)
	if err != nil {
		return tpm2.HandleNull, fmt.Errorf("failed to start auth session: %v", err)
	}

	sel := tpm2.PCRSelection{
		Hash: pcrHash,
		PCRs: pcrs,
	}
	if err = tpm2.PolicyPCR(rw, handle, nil, sel); err != nil {
		return tpm2.HandleNull, fmt.Errorf("auth step PolicyPCR failed: %v", err)
	}

	return handle, nil
}
