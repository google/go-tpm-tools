package client

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/sha512"
	"fmt"
	"reflect"
	"testing"

	"github.com/google/go-tpm-tools/internal"
	"github.com/google/go-tpm-tools/internal/test"

	"github.com/google/go-tpm/direct/structures/tpm"
	"github.com/google/go-tpm/direct/structures/tpml"
	"github.com/google/go-tpm/direct/structures/tpmt"
	"github.com/google/go-tpm/direct/tpm2"
	"github.com/google/go-tpm/direct/transport/simulator"
)

var extendsDirect = map[tpm.AlgID][]struct {
	digest []byte
}{
	tpm.AlgSHA1: {
		{bytes.Repeat([]byte{0x00}, sha1.Size)},
		{bytes.Repeat([]byte{0x01}, sha1.Size)},
		{bytes.Repeat([]byte{0x02}, sha1.Size)}},
	tpm.AlgSHA256: {
		{bytes.Repeat([]byte{0x00}, sha256.Size)},
		{bytes.Repeat([]byte{0x01}, sha256.Size)},
		{bytes.Repeat([]byte{0x02}, sha256.Size)}},
	tpm.AlgSHA384: {
		{bytes.Repeat([]byte{0x00}, sha512.Size384)},
		{bytes.Repeat([]byte{0x01}, sha512.Size384)},
		{bytes.Repeat([]byte{0x02}, sha512.Size384)}},
}

func simulatedPCRExtendDirect(alg tpm.AlgID, old, new []byte) ([]byte, error) {
	hCon, err := alg.Hash()
	if err != nil {
		return nil, fmt.Errorf("not a valid hash type: %v", alg)
	}
	h := hCon.New()
	h.Write(old)
	h.Write(new)
	return h.Sum(nil), nil
}
func TestReadPCRsDirect(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	cases := []struct {
		name    string
		hashalg tpm.AlgID
	}{
		{"SHA1", tpm.AlgSHA1},
		{"SHA256", tpm.AlgSHA256},
		{"SHA384", tpm.AlgSHA384},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			selection, err := internal.CreateTPMLPCRSelection([]uint32{uint32(test.DebugPCR)}, c.hashalg)
			if err != nil {
				t.Fatalf("Failed to create PCRSelection")
			}

			pcrRead := tpm2.PCRRead{
				PCRSelectionIn: selection,
			}

			pcrReadRsp, err := pcrRead.Execute(thetpm)
			if err != nil {
				t.Fatalf("failed to read PCRs")
			}

			pcr16val := pcrReadRsp.PCRValues.Digests[0].Buffer

			for _, d := range extendsDirect[c.hashalg] {

				pcrExtend := tpm2.PCRExtend{
					PCRHandle: tpm2.AuthHandle{
						Handle: tpm.Handle(test.DebugPCR),
						Auth:   tpm2.PasswordAuth(nil),
					},
					Digests: tpml.DigestValues{
						Digests: []tpmt.HA{
							{
								HashAlg: c.hashalg,
								Digest:  d.digest,
							},
						},
					},
				}

				if err := pcrExtend.Execute(thetpm); err != nil {
					t.Fatalf("failed to extend pcr for test %v", err)
				}

				pcrVal, err := simulatedPCRExtendDirect(c.hashalg, pcr16val, d.digest)
				if err != nil {
					t.Fatalf("could not extend pcr: %v", err)
				}

				pcr16val = pcrVal

				proto, err := readPCRsDirect(thetpm, selection.PCRSelections[0])
				if err != nil {
					t.Fatalf("failed to read pcrs %v", err)
				}

				if !bytes.Equal(proto.Pcrs[uint32(test.DebugPCR)], pcr16val) {
					t.Errorf("%v not equal to expected %v", proto.Pcrs[uint32(test.DebugPCR)], pcr16val)
				}
			}
		})
	}
}

func TestCheckContainedPCRsDirect(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	DebugPCR := uint32(test.DebugPCR)
	sel := fullPcrSelDirect(tpm.AlgSHA256)
	baseline, err := readPCRsDirect(thetpm, sel)
	if err != nil {
		t.Fatalf("Failed to Read PCRs: %v", err)
	}

	pcrs, err := internal.CreateTPMSPCRSelection([]uint32{DebugPCR}, tpm.AlgSHA256)
	if err != nil {
		t.Fatalf("Failed to create PCRSelection")
	}
	toBeCertified, err := readPCRsDirect(thetpm, pcrs)
	if err != nil {
		t.Fatalf("failed to read pcrs %v", err)
	}
	if err := internal.CheckSubset(toBeCertified, baseline); err != nil {
		t.Fatalf("Validation should pass: %v", err)
	}

	pcrExtend := tpm2.PCRExtend{
		PCRHandle: tpm2.AuthHandle{
			Handle: tpm.Handle(test.DebugPCR),
			Auth:   tpm2.PasswordAuth(nil),
		},
		Digests: tpml.DigestValues{
			Digests: []tpmt.HA{
				{
					HashAlg: tpm.AlgSHA256,
					Digest:  bytes.Repeat([]byte{0x00}, sha256.Size),
				},
			},
		},
	}
	if err = pcrExtend.Execute(thetpm); err != nil {
		t.Fatalf("failed to extend pcr for test %v", err)
	}

	pcrs, err = internal.CreateTPMSPCRSelection([]uint32{1, 3, DebugPCR}, tpm.AlgSHA256)
	if err != nil {
		t.Fatalf("Failed to create PCRSelection")
	}
	toBeCertified, err = readPCRsDirect(thetpm, pcrs)
	if err != nil {
		t.Fatalf("failed to read pcrs %v", err)
	}
	if err := internal.CheckSubset(toBeCertified, baseline); err == nil {
		t.Fatalf("validation should fail due to PCR %d changed", test.DebugPCR)
	}

	pcrs, err = internal.CreateTPMSPCRSelection([]uint32{}, tpm.AlgSHA256)
	if err != nil {
		t.Fatalf("Failed to create PCRSelection")
	}
	toBeCertified, err = readPCRsDirect(thetpm, pcrs)
	if err != nil {
		t.Fatalf("failed to read pcrs %v", err)
	}
	if err := internal.CheckSubset(toBeCertified, baseline); err != nil {
		t.Fatalf("Validation should pass: %v", err)
	}
}

func TestReadAllPCR(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	sel := fullPcrSelDirect(tpm.AlgSHA1)
	readFull, err := readPCRsDirect(thetpm, sel)
	if err != nil {
		t.Fatalf("Failed to Read PCRs: %v", err)
	}

	readAll, err := readAllPCRsDirect(thetpm)
	if err != nil {
		t.Fatalf("Failed to readAllPCRsDirect: %v", err)
	}

	if !reflect.DeepEqual(readFull, readAll[0]) {
		t.Fatalf("%v not equal to expected %v", readFull, readAll[0])
	}
}

func TestMergePCRSelAndProtoDirect(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	pcrs, err := internal.CreateTPMSPCRSelection([]uint32{1, 2, 3, 4}, tpm.AlgSHA256)
	if err != nil {
		t.Fatalf("Failed to create PCRSelection: %v", err)
	}
	mergeExpected, err := readPCRsDirect(thetpm, pcrs)
	if err != nil {
		t.Fatalf("Failed to readPCRsDirect: %v", err)
	}

	pcrs, err = internal.CreateTPMSPCRSelection([]uint32{1, 3}, tpm.AlgSHA256)
	if err != nil {
		t.Fatalf("Failed to create PCRSelection: %v", err)
	}
	proto, err := readPCRsDirect(thetpm, pcrs)
	if err != nil {
		t.Fatalf("Failed to readPCRsDirect: %v", err)
	}

	pcrs, err = internal.CreateTPMSPCRSelection([]uint32{2, 4}, tpm.AlgSHA256)
	if err != nil {
		t.Fatalf("Failed to create PCRSelection: %v", err)
	}

	mergeResult, err := mergePCRSelAndProtoDirect(thetpm, pcrs, proto)
	if err != nil {
		t.Fatalf("Failed to mergePCRSelAndProtoDirect: %v", err)
	}

	if !reflect.DeepEqual(mergeExpected, mergeResult) {
		t.Fatalf("%v not equal to expected %v", mergeExpected, mergeResult)
	}
}
