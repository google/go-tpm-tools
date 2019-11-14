package tpm2tools

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"testing"

	"github.com/google/go-tpm-tools/internal"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var tests = []struct {
	inAlg        tpm2.Algorithm
	inExtensions [][]byte
}{
	{tpm2.AlgSHA1, nil},
	{tpm2.AlgSHA1, [][]byte{bytes.Repeat([]byte{0x00}, sha1.Size)}},
	{tpm2.AlgSHA1, [][]byte{bytes.Repeat([]byte{0x01}, sha1.Size)}},
	{tpm2.AlgSHA1, [][]byte{bytes.Repeat([]byte{0x02}, sha1.Size)}},

	{tpm2.AlgSHA256, nil},
	{tpm2.AlgSHA256, [][]byte{bytes.Repeat([]byte{0x00}, sha256.Size)}},
	{tpm2.AlgSHA256, [][]byte{bytes.Repeat([]byte{0x01}, sha256.Size)}},
	{tpm2.AlgSHA256, [][]byte{bytes.Repeat([]byte{0x02}, sha256.Size)}},

	{tpm2.AlgSHA384, nil},
	{tpm2.AlgSHA384, [][]byte{bytes.Repeat([]byte{0x00}, sha512.Size384)}},
	{tpm2.AlgSHA384, [][]byte{bytes.Repeat([]byte{0x01}, sha512.Size384)}},
	{tpm2.AlgSHA384, [][]byte{bytes.Repeat([]byte{0x02}, sha512.Size384)}},
}

func pcrExtend(alg tpm2.Algorithm, old, new []byte) ([]byte, error) {
	hCon, err := alg.Hash()
	if err != nil {
		return nil, fmt.Errorf("not a valid hash type: %v", alg)
	}
	h := hCon.New()
	h.Write(old)
	h.Write(new)
	return h.Sum(nil), nil
}

func TestReadPCRs(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer CheckedClose(t, rwc)

	testPcrs := make(map[tpm2.Algorithm][]byte, 2)
	testPcrs[tpm2.AlgSHA1] = bytes.Repeat([]byte{0x00}, sha1.Size)
	testPcrs[tpm2.AlgSHA256] = bytes.Repeat([]byte{0x00}, sha256.Size)
	testPcrs[tpm2.AlgSHA384] = bytes.Repeat([]byte{0x00}, sha512.Size384)

	for _, test := range tests {
		for _, extension := range test.inExtensions {
			if err := tpm2.PCRExtend(rwc, tpmutil.Handle(0), test.inAlg, extension, ""); err != nil {
				t.Fatalf("failed to extend pcr for test %v", err)
			}

			pcrVal, err := pcrExtend(test.inAlg, testPcrs[test.inAlg], extension)
			if err != nil {
				t.Fatalf("could not extend pcr: %v", err)
			}
			testPcrs[test.inAlg] = pcrVal
		}

		sel := tpm2.PCRSelection{Hash: test.inAlg, PCRs: []int{0}}
		proto, err := ReadPCRs(rwc, sel)
		if err != nil {
			t.Fatalf("failed to read pcrs %v", err)
		}

		if !bytes.Equal(proto.Pcrs[0], testPcrs[test.inAlg]) {
			t.Errorf("%v not equal to expected %v", proto.Pcrs[0], testPcrs[test.inAlg])
		}
	}
}

func TestGetPCRCount(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer CheckedClose(t, rwc)
	pcrCount, err := GetPCRCount(rwc)
	if err != nil {
		t.Fatalf("Failed to fetch pcr count: %v", err)
	}

	if pcrCount != 24 {
		t.Errorf("tpm simulator has unexpected number of PCRs: %v instead of 24", pcrCount)
	}
}

// func TestCurrentPCR(t *testing.T) {
// 	rwc := internal.GetTPM(t)
// 	defer CheckedClose(t, rwc)

// 	pcrList := []int{1, 7}
// 	currentPCRSelection := tpm2.PCRSelection{
// 		Hash: tpm2.AlgSHA256,
// 		PCRs: pcrList,
// 	}
// 	currentPCR := SealCurrent{PCRSelection: currentPCRSelection}
// 	proto, err := ReadPCRs(rwc, currentPCRSelection)
// 	if err != nil {
// 		t.Fatalf("fail to read PCRs: %v", err)
// 	}
// 	computedDigest := computePCRDigest(proto)

// 	if !reflect.DeepEqual(currentPCR.GetPCRSelection(), currentPCRSelection) {
// 		t.Fatalf("GetPCRSelection not euqal to expect")
// 	}

// 	pcrForSealing, err := currentPCR.PCRsForSealing(rwc)
// 	if err != nil {
// 		t.Fatalf("fail to computeDigest: %v", err)
// 	}
// 	if !reflect.DeepEqual(pcrForSealing, proto) {
// 		t.Fatalf("PCRForSealing not equal to expect")
// 	}

// 	if err = currentPCR.CertifyPCRs(rwc, computedDigest); err != nil {
// 		t.Fatalf("CertifyPCRs failed: %v", err)
// 	}
// }

// func TestTargetPCR(t *testing.T) {
// 	rwc := internal.GetTPM(t)
// 	defer CheckedClose(t, rwc)

// 	pcrList := []int{7}
// 	expectedPCRSelection := tpm2.PCRSelection{
// 		Hash: tpm2.AlgSHA256,
// 		PCRs: pcrList,
// 	}

// 	proto, err := ReadPCRs(rwc, expectedPCRSelection)
// 	if err != nil {
// 		t.Fatalf("Failed to read pcr: %v", err)
// 	}
// 	targetPCR := TargetPCRs{proto}

// 	if !reflect.DeepEqual(targetPCR.GetPCRSelection(), expectedPCRSelection) {
// 		t.Fatalf("GetPCRSelection not equal to expect")
// 	}

// 	pcrForSealing, err := targetPCR.PCRsForSealing(nil)
// 	if err != nil {
// 		t.Fatalf("Failed to get get PCRsForSealing")
// 	}
// 	if !reflect.DeepEqual(pcrForSealing, proto) {
// 		t.Fatal("PCRForSealing not equal to expect")
// 	}
// }

// func TestExpectedPCR(t *testing.T) {
// 	rwc := internal.GetTPM(t)
// 	defer CheckedClose(t, rwc)

// 	pcrList := []int{1, 7}
// 	expectedPCRSelection := tpm2.PCRSelection{
// 		Hash: tpm2.AlgSHA256,
// 		PCRs: pcrList,
// 	}
// 	proto, err := ReadPCRs(rwc, expectedPCRSelection)
// 	computedDigest := computePCRDigest(proto)

// 	expectedPCRs := ExpectedPCRs{proto}
// 	if err = expectedPCRs.CertifyPCRs(nil, computedDigest); err != nil {
// 		t.Fatalf("CertifyPCRs failed: %v", err)
// 	}
// }
