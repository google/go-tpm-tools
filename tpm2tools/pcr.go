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

// SealCurrent represent current PCRs states.
type SealCurrent struct{ tpm2.PCRSelection }

// SealTarget predicted sealing target PCRs.
type SealTarget struct{ *proto.Pcrs }

// SealingOpt will return a set of target PCRs when sealing.
type SealingOpt interface {
	PCRsForSealing(rw io.ReadWriter) (*proto.Pcrs, error)
}

// PCRsForSealing read from TPM and return the selected PCRs.
func (p SealCurrent) PCRsForSealing(rw io.ReadWriter) (*proto.Pcrs, error) {
	if p.PCRSelection.PCRs == nil {
		panic("SealCurrent contains 0 PCRs")
	}
	return ReadPCRs(rw, p.PCRSelection)
}

// PCRsForSealing return the target PCRs.
func (p SealTarget) PCRsForSealing(_ io.ReadWriter) (*proto.Pcrs, error) {
	if p.Pcrs == nil || len(p.Pcrs.GetPcrs()) == 0 {
		panic("SealTarget contains 0 PCRs")
	}
	return p.Pcrs, nil
}

// CertifyCurrent represent a PCR selection for ceritfy.
type CertifyCurrent struct{ tpm2.PCRSelection }

// CertifyExpected should match the old PCRs.
type CertifyExpected struct{ *proto.Pcrs }

// CertificationOpt is an interface to certify keys created by create().
type CertificationOpt interface {
	CertifyPCRs(rw io.ReadWriter, certified *proto.Pcrs) error
}

// CertifyPCRs from CurrentPCRs will read PCR values from TPM and compare the digest.
func (p CertifyCurrent) CertifyPCRs(rw io.ReadWriter, pcrs *proto.Pcrs) error {
	current, err := ReadPCRs(rw, p.PCRSelection)
	if err != nil {
		return err
	}
	return validateCertifyPCRs(current, pcrs)
}

// CertifyPCRs will compare the digest with given expected PCRs values.
func (p CertifyExpected) CertifyPCRs(_ io.ReadWriter, pcrs *proto.Pcrs) error {
	return validateCertifyPCRs(p.Pcrs, pcrs)
}

func validateCertifyPCRs(toBeCertified *proto.Pcrs, truth *proto.Pcrs) error {
	var pcrList []uint32
	for pcrNum, pcrVal := range toBeCertified.GetPcrs() {
		if expectedVal, ok := truth.GetPcrs()[pcrNum]; ok {
			if !bytes.Equal(expectedVal, pcrVal) {
				pcrList = append(pcrList, pcrNum)
			}
		} else {
			// pcr # out of bound (not within 0-23)
			panic("PCR " + string(pcrNum) + " not existed in the certified PCRs")
		}
	}

	if len(pcrList) > 0 {
		return fmt.Errorf("Certify PCRs not matching: %v", pcrList)
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

// FullPcrSel will return a full pcr selection (24 pcrs) with the given
// hash algo.
func FullPcrSel(hash tpm2.Algorithm) tpm2.PCRSelection {
	sel := tpm2.PCRSelection{Hash: hash}
	for i := 0; i < 24; i++ {
		sel.PCRs = append(sel.PCRs, int(i))
	}
	return sel
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
