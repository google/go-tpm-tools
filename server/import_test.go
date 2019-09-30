package server

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm-tools/internal"
	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
)

func TestImport(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer tpm2tools.CheckedClose(t, rwc)
	tests := []struct {
		name     string
		template tpm2.Public
	}{
		{"RSA", tpm2tools.DefaultEKTemplateRSA()},
		{"ECC", tpm2tools.DefaultEKTemplateECC()},
		{"ECC-P224", getECCTemplate(tpm2.CurveNISTP224)},
		{"ECC-P256", getECCTemplate(tpm2.CurveNISTP256)},
		{"ECC-P384", getECCTemplate(tpm2.CurveNISTP384)},
		{"ECC-P521", getECCTemplate(tpm2.CurveNISTP521)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ek, err := tpm2tools.NewKey(rwc, tpm2.HandleEndorsement, test.template)
			if err != nil {
				t.Fatal(err)
			}
			defer ek.Close()
			pub := ek.PublicKey()
			secret := []byte("super secret code")
			blob, err := CreateImportBlob(pub, secret)
			if err != nil {
				t.Fatalf("creating import blob failed: %v", err)
			}

			output, err := ek.Import(rwc, blob)
			if err != nil {
				t.Fatalf("import failed: %v", err)
			}
			if !bytes.Equal(output, secret) {
				t.Errorf("got %X, expected %X", output, secret)
			}
		})
	}
}

func TestImport(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer tpm2tools.CheckedClose(t, rwc)

	ek, err := tpm2tools.EndorsementKeyRSA(rwc)
	if err != nil {
		t.Fatal(err)
	}
	defer ek.Close()
	pcr0, err := tpm2.ReadPCR(rwc, 0, tpm2.AlgSHA256)
	if err != nil {
		t.Fatal(err)
	badPCR := append([]byte(nil), pcr0...)
	// badPCR increments first value so it doesn't match.
	badPCR[0]++
	tests := []struct {
		name          string
		pcrMap        map[int][]byte
		expectSuccess bool
	}{
		{"No-PCR", nil, true},
		{"Good-PCR", map[int][]byte{0: pcr0}, true},
		{"Bad-PCR", map[int][]byte{0: badPCR}, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			secret := []byte("super secret code")
			blob, err := CreateImportBlob(ek.PublicKey(), secret, test.pcrMap)
			if err != nil {
				t.Fatalf("creating import blob failed: %v", err)
			}

			output, err := ek.Import(rwc, blob)
			if !test.expectSuccess {
				if err == nil {
					t.Error("expected Import to fail but it did not")
				}
				return
			}
			if err != nil {
				t.Fatalf("import failed: %v", err)
			}
			if !bytes.Equal(output, secret) {
				t.Errorf("got %X, expected %X", output, secret)
			}
		})
	}
}
