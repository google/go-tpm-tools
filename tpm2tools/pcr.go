package tpm2tools

import (
	"bytes"
	"crypto"
	"fmt"
	"io"

	"github.com/google/go-tpm-tools/proto"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// We hard-code SHA256 as the policy session hash algorithms. Note that this
// differs from the PCR hash algorithm (which selects the bank of PCRs to use)
// and the Public area Name algorithm. We also chose this for compatibility with
// github.com/google/go-tpm/tpm2, as it hardcodes the nameAlg as SHA256 in
// several places. Two constants are used to avoid repeated conversions.
const sessionHashAlg = crypto.SHA256
const sessionHashAlgTpm = tpm2.AlgSHA256

// CertifyHashAlgTpm is the hard-coded algorithm used in certify PCRs.
const CertifyHashAlgTpm = tpm2.AlgSHA256

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

// ReadPCRs fetches all the PCR values specified in sel, making multiple calls
// to the TPM if necessary.
func ReadPCRs(rw io.ReadWriter, sel tpm2.PCRSelection) (*proto.Pcrs, error) {
	pl := proto.Pcrs{
		Hash: proto.HashAlgo(sel.Hash),
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

// SealCurrent seals data to the current specified PCR selection.
type SealCurrent struct{ tpm2.PCRSelection }

// SealTarget predicatively seals data to the given specified PCR values.
type SealTarget struct{ *proto.Pcrs }

// SealOpt specifies the PCR values that should be used for Seal().
type SealOpt interface {
	PCRsForSealing(rw io.ReadWriter) (*proto.Pcrs, error)
}

// PCRsForSealing read from TPM and return the selected PCRs.
func (p SealCurrent) PCRsForSealing(rw io.ReadWriter) (*proto.Pcrs, error) {
	if len(p.PCRSelection.PCRs) == 0 {
		panic("SealCurrent contains 0 PCRs")
	}
	return ReadPCRs(rw, p.PCRSelection)
}

// PCRsForSealing return the target PCRs.
func (p SealTarget) PCRsForSealing(_ io.ReadWriter) (*proto.Pcrs, error) {
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
type CertifyExpected struct{ *proto.Pcrs }

// CertifyOpt determines if the given PCR value can pass certification in Unseal().
type CertifyOpt interface {
	CertifyPCRs(rw io.ReadWriter, certified *proto.Pcrs) error
}

// CertifyPCRs from CurrentPCRs will read PCR values from TPM and compare the digest.
func (p CertifyCurrent) CertifyPCRs(rw io.ReadWriter, pcrs *proto.Pcrs) error {
	if len(p.PCRSelection.PCRs) == 0 {
		panic("CertifyCurrent contains 0 PCRs")
	}
	current, err := ReadPCRs(rw, p.PCRSelection)
	if err != nil {
		return err
	}
	return checkContainedPCRs(current, pcrs)
}

// CertifyPCRs will compare the digest with given expected PCRs values.
func (p CertifyExpected) CertifyPCRs(_ io.ReadWriter, pcrs *proto.Pcrs) error {
	if len(p.Pcrs.GetPcrs()) == 0 {
		panic("CertifyExpected contains 0 PCRs")
	}
	return checkContainedPCRs(p.Pcrs, pcrs)
}

// Check if the "superset" PCRs contain a valid "subset" PCRs, the PCR value must match
// If there is one or more PCRs in subset which don't exist in superset, will return
// an error with the first missing PCR.
// If there is one or more PCRs value mismatch with the superset, will return an error
// with the first mismatched PCR numbers.
func checkContainedPCRs(subset *proto.Pcrs, superset *proto.Pcrs) error {
	if subset.GetHash() != superset.GetHash() {
		return fmt.Errorf("PCR hash algo not matching: %v, %v", subset.GetHash(), superset.GetHash())
	}
	for pcrNum, pcrVal := range subset.GetPcrs() {
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

// PCRSelection returns the corresponding tpm2.PCRSelection for a proto.Pcrs
func PCRSelection(pcrs *proto.Pcrs) tpm2.PCRSelection {
	sel := tpm2.PCRSelection{Hash: tpm2.Algorithm(pcrs.Hash)}

	for pcrNum := range pcrs.Pcrs {
		sel.PCRs = append(sel.PCRs, int(pcrNum))
	}
	return sel
}

// EqualsPCRSelections compares the given tpm2.PCRSelections (including
// the hash algo), and will return an error if they are not equal.
func EqualsPCRSelections(a tpm2.PCRSelection, b tpm2.PCRSelection) error {
	if a.Hash != b.Hash {
		return fmt.Errorf("hash algorithm not equal")
	}
	diff := make(map[int]int, len(a.PCRs))
	for _, pcr := range a.PCRs {
		diff[pcr]++
	}
	for _, pcr := range b.PCRs {
		if _, ok := diff[pcr]; !ok {
			return fmt.Errorf("PCR selection not equal")
		}
		diff[pcr]--
		if diff[pcr] == 0 {
			delete(diff, pcr)
		}
	}
	if len(diff) != 0 {
		return fmt.Errorf("PCR selection not equal")
	}
	return nil
}

// FullPcrSel will return a full PCR selection based on the total PCR number
// of the TPM with the given hash algo.
func FullPcrSel(hash tpm2.Algorithm, rw io.ReadWriter) (tpm2.PCRSelection, error) {
	sel := tpm2.PCRSelection{Hash: hash}
	count, err := GetPCRCount(rw)
	if err != nil {
		return sel, err
	}
	for i := 0; i < int(count); i++ {
		sel.PCRs = append(sel.PCRs, int(i))
	}
	return sel, nil
}

// ComputePCRSessionAuth calculates the authorization value for the given PCRs.
func ComputePCRSessionAuth(pcrs *proto.Pcrs) []byte {
	// Start with all zeros, we only use a single policy command on our session.
	oldDigest := make([]byte, sessionHashAlg.Size())
	ccPolicyPCR, _ := tpmutil.Pack(tpm2.CmdPolicyPCR)

	// Extend the policy digest, see TPM2_PolicyPCR in Part 3 of the spec.
	hash := sessionHashAlg.New()
	hash.Write(oldDigest)
	hash.Write(ccPolicyPCR)
	hash.Write(encodePCRSelection(PCRSelection(pcrs)))
	hash.Write(computePCRDigest(pcrs))
	newDigest := hash.Sum(nil)
	return newDigest[:]
}

// ComputePCRDigest will take in a PCR proto and compute the digest based on the
// given PCR proto.
func computePCRDigest(pcrs *proto.Pcrs) []byte {
	hash := sessionHashAlg.New()
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

func createPCRSession(rw io.ReadWriter, sel tpm2.PCRSelection) (tpmutil.Handle, error) {
	// This session assumes the bus is trusted, so we:
	// - use nil for tpmkey, encrypted salt, and symmetric
	// - use and all-zeros caller nonce, and ignore the returned nonce
	// As we are creating a plain TPM session, we:
	// - setup a policy session
	// - don't bind the session to any particular key
	handle, _, err := tpm2.StartAuthSession(
		rw,
		/*tpmkey=*/ tpm2.HandleNull,
		/*bindkey=*/ tpm2.HandleNull,
		/*nonceCaller=*/ make([]byte, sessionHashAlg.Size()),
		/*encryptedSalt=*/ nil,
		/*sessionType=*/ tpm2.SessionPolicy,
		/*symmetric=*/ tpm2.AlgNull,
		/*authHash=*/ sessionHashAlgTpm)
	if err != nil {
		return tpm2.HandleNull, fmt.Errorf("failed to start auth session: %v", err)
	}

	if err = tpm2.PolicyPCR(rw, handle, nil, sel); err != nil {
		return tpm2.HandleNull, fmt.Errorf("auth step PolicyPCR failed: %v", err)
	}
	return handle, nil
}
