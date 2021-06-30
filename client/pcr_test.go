package client_test

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal"
	"github.com/google/go-tpm-tools/internal/test"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

var extends = []struct {
	alg     tpm2.Algorithm
	digests [][]byte
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
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	testPcrs := make(map[tpm2.Algorithm][]byte)
	testPcrs[tpm2.AlgSHA1] = bytes.Repeat([]byte{0x00}, sha1.Size)
	testPcrs[tpm2.AlgSHA256] = bytes.Repeat([]byte{0x00}, sha256.Size)
	testPcrs[tpm2.AlgSHA384] = bytes.Repeat([]byte{0x00}, sha512.Size384)

	for _, extend := range extends {
		for _, digest := range extend.digests {
			if err := tpm2.PCRExtend(rwc, tpmutil.Handle(test.DebugPCR), extend.alg, digest, ""); err != nil {
				t.Fatalf("failed to extend pcr for test %v", err)
			}

			pcrVal, err := pcrExtend(extend.alg, testPcrs[extend.alg], digest)
			if err != nil {
				t.Fatalf("could not extend pcr: %v", err)
			}
			testPcrs[extend.alg] = pcrVal
		}

		sel := tpm2.PCRSelection{Hash: extend.alg, PCRs: []int{test.DebugPCR}}
		proto, err := client.ReadPCRs(rwc, sel)
		if err != nil {
			t.Fatalf("failed to read pcrs %v", err)
		}

		if !bytes.Equal(proto.Pcrs[uint32(test.DebugPCR)], testPcrs[extend.alg]) {
			t.Errorf("%v not equal to expected %v", proto.Pcrs[0], testPcrs[extend.alg])
		}
	}
}

func TestCheckContainedPCRs(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	sel := client.FullPcrSel(tpm2.AlgSHA256)
	baseline, err := client.ReadPCRs(rwc, sel)
	if err != nil {
		t.Fatalf("Failed to Read PCRs: %v", err)
	}

	toBeCertified, err := client.ReadPCRs(rwc, tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{1, 2, 3}})
	if err != nil {
		t.Fatalf("failed to read pcrs %v", err)
	}
	if err := internal.CheckSubset(toBeCertified, baseline); err != nil {
		t.Fatalf("Validation should pass: %v", err)
	}

	if err := tpm2.PCRExtend(rwc, tpmutil.Handle(test.DebugPCR), tpm2.AlgSHA256, bytes.Repeat([]byte{0x00}, sha256.Size), ""); err != nil {
		t.Fatalf("failed to extend pcr for test %v", err)
	}

	toBeCertified, err = client.ReadPCRs(rwc, tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{1, 3, test.DebugPCR}})
	if err != nil {
		t.Fatalf("failed to read pcrs %v", err)
	}
	if err := internal.CheckSubset(toBeCertified, baseline); err == nil {
		t.Fatalf("validation should fail due to PCR %d changed", test.DebugPCR)
	}

	toBeCertified, err = client.ReadPCRs(rwc, tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{}})
	if err != nil {
		t.Fatalf("failed to read pcrs %v", err)
	}
	if err := internal.CheckSubset(toBeCertified, baseline); err != nil {
		t.Fatalf("empty pcrs is always validate")
	}
}
