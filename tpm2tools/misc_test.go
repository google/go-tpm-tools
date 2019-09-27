package tpm2tools

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"testing"

	"github.com/google/go-tpm-tools/internal"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var tests = []struct {
	inPcrs       []int
	inAlg        tpm2.Algorithm
	inExtensions [][]byte
	out          []byte
}{
	{[]int{0}, tpm2.AlgSHA1, nil, bytes.Repeat([]byte{0x00}, sha1.Size)},
	{[]int{0}, tpm2.AlgSHA1, [][]byte{bytes.Repeat([]byte{0x00}, sha1.Size)}, []byte{184, 13, 229, 209, 56, 117, 133, 65, 197, 240, 82, 101, 173, 20, 74, 185, 250, 134, 209, 219}},
	{[]int{0}, tpm2.AlgSHA256, nil, bytes.Repeat([]byte{0x00}, sha256.Size)},
	{[]int{0}, tpm2.AlgSHA256, [][]byte{bytes.Repeat([]byte{0x00}, sha256.Size)}, []byte{245, 165, 253, 66, 209, 106, 32, 48, 39, 152, 239, 110, 211, 9, 151, 155, 67, 0, 61, 35, 32, 217, 240, 232, 234, 152, 49, 169, 39, 89, 251, 75}},
}

func TestReadPCRs(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer CheckedClose(t, rwc)

	for _, test := range tests {
		for _, extension := range test.inExtensions {
			err := tpm2.PCRExtend(rwc, tpmutil.Handle(0), test.inAlg, extension, "")

			if err != nil {
				t.Fatalf("failed to extend pcr for test %v", err)
			}
		}

		proto, err := ReadPCRs(rwc, test.inPcrs, test.inAlg)
		if err != nil {
			t.Fatalf("failed to read pcrs %v", err)
		}

		if !bytes.Equal(proto.Pcrs[0], test.out) {
			t.Fatalf("%v not equal to expected %v", proto.Pcrs[0], test.out)
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
		t.Fatalf("tpm simulator has unexpected number of PCRs: %v instead of 24", pcrCount)
	}

}
