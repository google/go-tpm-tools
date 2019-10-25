package tpm2tools

import (
	"crypto/subtle"
	"fmt"
	"io"
	"sort"

	"github.com/google/go-tpm-tools/proto"
	"github.com/google/go-tpm/tpm2"
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

// ComputePCRDigest will take in a PCR proto and compute the SHA256 digest based on the
// given PCR proto.
// Followed PCRComputeCurrentDigest() in the TPM spec.
func ComputePCRDigest(pcrs *proto.Pcrs, hashAlg tpm2.Algorithm) ([]byte, error) {
	hash, err := hashAlg.Hash()
	if err != nil {
		return nil, err
	}
	hashCon := hash.New()

	pcrMap := pcrs.GetPcrs()
	pcrsList := make([]int, 0, len(pcrMap))
	for k := range pcrMap {
		pcrsList = append(pcrsList, int(k))
	}
	sort.Ints(pcrsList)
	for _, pcrNum := range pcrsList {
		hashCon.Write(pcrMap[uint32(pcrNum)])
	}
	return hashCon.Sum(nil), nil
}

// CurrentPCRs represent current PCRs states
type CurrentPCRs struct {
	PCRSel tpm2.PCRSelection
	RW     io.ReadWriteCloser
}

// ExpectedPCRs should match the old PCRs.
type ExpectedPCRs struct{ *proto.Pcrs }

// TargetPCRs predicted sealing target PCRs.
type TargetPCRs struct{ *proto.Pcrs }

// SealingConfig will return a set of target PCRs when sealing.
type SealingConfig interface {
	PCRsForSealing() (*proto.Pcrs, error)
}

// PCRsForSealing return the target PCRs.
func (p TargetPCRs) PCRsForSealing() (*proto.Pcrs, error) {
	return p.Pcrs, nil
}

// PCRsForSealing read from TPM and return the selected PCRs.
func (p CurrentPCRs) PCRsForSealing() (*proto.Pcrs, error) {
	pcrVals, err := ReadPCRs(p.RW, p.PCRSel.PCRs, p.PCRSel.Hash)
	if err != nil {
		return nil, err
	}
	return pcrVals, nil
}

// CertificationConfig is an interface to certify create().
type CertificationConfig interface {
	CertifyPCRs(pcrs *proto.Pcrs, digest []byte) error
}

// CertifyPCRs from CurrentPCRs will read from TPM and compare the digest.
func (p CurrentPCRs) CertifyPCRs(pcrs *proto.Pcrs, digest []byte) error {
	pcrVals, err := ReadPCRs(p.RW, p.PCRSel.PCRs, p.PCRSel.Hash)
	if err != nil {
		return err
	}
	computedDigest, err := ComputePCRDigest(pcrVals, tpm2.AlgSHA256)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(computedDigest, digest) == 0 {
		return fmt.Errorf("certify failed, current PCR digest not matching when create")
	}
	return nil
}

// CertifyPCRs will compare the digest with given expected PCRs values.
func (p ExpectedPCRs) CertifyPCRs(pcrs *proto.Pcrs, digest []byte) error {
	computedDigest, err := ComputePCRDigest(p.Pcrs, tpm2.AlgSHA256)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(computedDigest, digest) == 0 {
		return fmt.Errorf("Certify failed, current PCR digest not matching when sealing")
	}
	return nil
}
