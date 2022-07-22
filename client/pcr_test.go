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

	"github.com/google/go-tpm/direct/structures/tpm"
	"github.com/google/go-tpm/direct/structures/tpml"
	"github.com/google/go-tpm/direct/structures/tpms"
	"github.com/google/go-tpm/direct/structures/tpmt"
	tpm2direct "github.com/google/go-tpm/direct/tpm2"
	"github.com/google/go-tpm/direct/transport/simulator"
)

var extends = map[tpm2.Algorithm][]struct {
	digest []byte
}{
	tpm2.AlgSHA1: {
		{bytes.Repeat([]byte{0x00}, sha1.Size)},
		{bytes.Repeat([]byte{0x01}, sha1.Size)},
		{bytes.Repeat([]byte{0x02}, sha1.Size)}},
	tpm2.AlgSHA256: {
		{bytes.Repeat([]byte{0x00}, sha256.Size)},
		{bytes.Repeat([]byte{0x01}, sha256.Size)},
		{bytes.Repeat([]byte{0x02}, sha256.Size)}},
	tpm2.AlgSHA384: {
		{bytes.Repeat([]byte{0x00}, sha512.Size384)},
		{bytes.Repeat([]byte{0x01}, sha512.Size384)},
		{bytes.Repeat([]byte{0x02}, sha512.Size384)}},
}

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

func simulatedPCRExtend(alg tpm2.Algorithm, old, new []byte) ([]byte, error) {
	hCon, err := alg.Hash()
	if err != nil {
		return nil, fmt.Errorf("not a valid hash type: %v", alg)
	}
	h := hCon.New()
	h.Write(old)
	h.Write(new)
	return h.Sum(nil), nil
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

func TestReadPCRs(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	cases := []struct {
		name    string
		hashalg tpm2.Algorithm
	}{
		{"SHA1", tpm2.AlgSHA1},
		{"SHA256", tpm2.AlgSHA256},
		{"SHA384", tpm2.AlgSHA384},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			test.SkipOnUnsupportedAlg(t, rwc, c.hashalg)

			pcrbank, err := tpm2.ReadPCR(rwc, test.DebugPCR, c.hashalg)
			if err != nil {
				t.Fatal(err)
			}

			for _, d := range extends[c.hashalg] {
				if err := tpm2.PCRExtend(rwc, tpmutil.Handle(test.DebugPCR), c.hashalg, d.digest, ""); err != nil {
					t.Fatalf("failed to extend pcr for test %v", err)
				}
				pcrVal, err := simulatedPCRExtend(c.hashalg, pcrbank, d.digest)
				if err != nil {
					t.Fatalf("could not extend pcr: %v", err)
				}
				pcrbank = pcrVal
				sel := tpm2.PCRSelection{Hash: c.hashalg, PCRs: []int{test.DebugPCR}}
				proto, err := client.ReadPCRs(rwc, sel)
				if err != nil {
					t.Fatalf("failed to read pcrs %v", err)
				}
				if !bytes.Equal(proto.Pcrs[uint32(test.DebugPCR)], pcrbank) {
					t.Errorf("%v not equal to expected %v", proto.Pcrs[uint32(test.DebugPCR)], pcrbank)
				}
			}
		})
	}
}

func createPCRSelection(s []int) ([]byte, error) {

	const sizeOfPCRSelect = 3

	PCRs := make(tpmutil.RawBytes, sizeOfPCRSelect)

	for _, n := range s {
		if n >= 8*sizeOfPCRSelect {
			return nil, fmt.Errorf("PCR index %d is out of range (exceeds maximum value %d)", n, 8*sizeOfPCRSelect-1)
		}
		byteNum := n / 8
		bytePos := byte(1 << (n % 8))
		PCRs[byteNum] |= bytePos
	}

	return PCRs, nil
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
			PCRs, err := createPCRSelection([]int{test.DebugPCR})
			if err != nil {
				t.Fatalf("Failed to create PCRSelection")
			}

			selection := tpml.PCRSelection{
				PCRSelections: []tpms.PCRSelection{
					{
						Hash:      c.hashalg,
						PCRSelect: PCRs,
					},
				},
			}

			pcrRead := tpm2direct.PCRRead{
				PCRSelectionIn: selection,
			}

			pcrReadRsp, err := pcrRead.Execute(thetpm)
			if err != nil {
				t.Fatalf("failed to read PCRs")
			}

			pcr16val := pcrReadRsp.PCRValues.Digests[0].Buffer

			for _, d := range extendsDirect[c.hashalg] {

				pcrExtend := tpm2direct.PCRExtend{
					PCRHandle: tpm2direct.AuthHandle{
						Handle: tpm.Handle(test.DebugPCR),
						Auth:   tpm2direct.PasswordAuth(nil),
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

				proto, err := client.ReadPCRsDirect(thetpm, selection.PCRSelections[0])
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

func TestCheckContainedPCRsDirect(t *testing.T) {
	thetpm, err := simulator.OpenSimulator()
	if err != nil {
		t.Fatalf("could not connect to TPM simulator: %v", err)
	}
	defer thetpm.Close()

	sel := client.FullPcrSelDirect(tpm.AlgSHA256)
	baseline, err := client.ReadPCRsDirect(thetpm, sel)
	if err != nil {
		t.Fatalf("Failed to Read PCRs: %v", err)
	}

	pcrs, err := createPCRSelection([]int{test.DebugPCR})
	if err != nil {
		t.Fatalf("Failed to create PCRSelection")
	}
	toBeCertified, err := client.ReadPCRsDirect(thetpm, tpms.PCRSelection{Hash: tpm.AlgSHA256, PCRSelect: pcrs})
	if err != nil {
		t.Fatalf("failed to read pcrs %v", err)
	}
	if err := internal.CheckSubset(toBeCertified, baseline); err != nil {
		t.Fatalf("Validation should pass: %v", err)
	}

	pcrExtend := tpm2direct.PCRExtend{
		PCRHandle: tpm2direct.AuthHandle{
			Handle: tpm.Handle(test.DebugPCR),
			Auth:   tpm2direct.PasswordAuth(nil),
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

	pcrs, err = createPCRSelection([]int{1, 3, test.DebugPCR})
	if err != nil {
		t.Fatalf("Failed to create PCRSelection")
	}
	toBeCertified, err = client.ReadPCRsDirect(thetpm, tpms.PCRSelection{Hash: tpm.AlgSHA256, PCRSelect: pcrs})
	if err != nil {
		t.Fatalf("failed to read pcrs %v", err)
	}
	if err := internal.CheckSubset(toBeCertified, baseline); err == nil {
		t.Fatalf("validation should fail due to PCR %d changed", test.DebugPCR)
	}

	pcrs, err = createPCRSelection([]int{})
	if err != nil {
		t.Fatalf("Failed to create PCRSelection")
	}
	toBeCertified, err = client.ReadPCRsDirect(thetpm, tpms.PCRSelection{Hash: tpm.AlgSHA256, PCRSelect: pcrs})
	if err != nil {
		t.Fatalf("failed to read pcrs %v", err)
	}
	if err := internal.CheckSubset(toBeCertified, baseline); err != nil {
		t.Fatalf("Validation should pass: %v", err)
	}
}
