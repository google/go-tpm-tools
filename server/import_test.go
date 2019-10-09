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
