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
type CurrentPCRs struct{ tpm2.PCRSelection }

// ExpectedPCRs should match the old PCRs.
type ExpectedPCRs struct{ *proto.Pcrs }

// TargetPCRs predicted sealing target PCRs.
type TargetPCRs struct{ *proto.Pcrs }

// SealingOpt will return a set of target PCRs when sealing.
type SealingOpt interface {
	PCRsForSealing(rw io.ReadWriter) (*proto.Pcrs, error)
	GetPCRSelection() tpm2.PCRSelection
}

// PCRsForSealing return the target PCRs.
func (p TargetPCRs) PCRsForSealing(_ io.ReadWriter) (*proto.Pcrs, error) {
	if p.Pcrs == nil || len(p.Pcrs.GetPcrs()) == 0 {
		panic("TargetPCRs contains 0 PCRs")
	}
	return p.Pcrs, nil
}

// GetPCRSelection will return the PCRSelection extracted from a PCR proto.
func (p TargetPCRs) GetPCRSelection() tpm2.PCRSelection {
	pcrMap := p.GetPcrs()
	pcrList := make([]int, 0, len(pcrMap))
	for k := range pcrMap {
		pcrList = append(pcrList, int(k))
	}
	sel := tpm2.PCRSelection{
		Hash: tpm2.Algorithm(p.Pcrs.GetHash()),
		PCRs: pcrList,
	}
	return sel
}

// PCRsForSealing read from TPM and return the selected PCRs.
func (p CurrentPCRs) PCRsForSealing(rw io.ReadWriter) (*proto.Pcrs, error) {
	if p.PCRSelection.PCRs == nil || len(p.PCRSelection.PCRs) == 0 {
		panic("CurrentPCRs contains 0 PCRs")
	}
	if rw == nil {
		panic("io.ReadWriter cannot be nil for CurrentPCRs")
	}

	pcrVals, err := ReadPCRs(rw, p.PCRSelection.PCRs, p.PCRSelection.Hash)
	if err != nil {
		return nil, err
	}
	return pcrVals, nil
}

// GetPCRSelection just return the PCRSelection.
func (p CurrentPCRs) GetPCRSelection() tpm2.PCRSelection {
	return p.PCRSelection
}

// CertificationOpt is an interface to certify keys created by create().
type CertificationOpt interface {
	CertifyPCRs(rw io.ReadWriter, digest []byte) error
}

// CertifyPCRs from CurrentPCRs will read PCR values from TPM and compare the digest.
func (p CurrentPCRs) CertifyPCRs(rw io.ReadWriter, digest []byte) error {
	if p.PCRSelection.PCRs == nil || len(p.PCRSelection.PCRs) == 0 {
		panic("CurrentPCRs contains nil or 0 PCRs")
	}
	if rw == nil {
		panic("io.ReadWriter cannot be nil for CurrentPCRs")
	}
	pcrVals, err := ReadPCRs(rw, p.PCRSelection.PCRs, p.PCRSelection.Hash)
	if err != nil {
		return err
	}
	return validatePCRDigest(pcrVals, digest)
}

// CertifyPCRs will compare the digest with given expected PCRs values.
func (p ExpectedPCRs) CertifyPCRs(_ io.ReadWriter, digest []byte) error {
	if p.Pcrs == nil || len(p.Pcrs.GetPcrs()) == 0 {
		panic("ExpectedPCRs contains nil or 0 PCRs")
	}
	return validatePCRDigest(p.Pcrs, digest)
}

func validatePCRDigest(pcrs *proto.Pcrs, digest []byte) error {
	computedDigest, err := ComputePCRDigest(pcrs, tpm2.AlgSHA256)
	if err != nil {
		return err
	}
	if subtle.ConstantTimeCompare(computedDigest, digest) == 0 {
		return fmt.Errorf("PCR digest not matching")
	}
	return nil
}
