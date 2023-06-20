package server

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/legacy/tpm2"
)

func TestImport(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	keys := []struct {
		name     string
		template tpm2.Public
	}{
		{"RSA", client.DefaultEKTemplateRSA()},
		{"ECC", client.DefaultEKTemplateECC()},
		{"SRK-RSA", client.SRKTemplateRSA()},
		{"SRK-ECC", client.SRKTemplateECC()},
		{"ECC-P224", getECCTemplate(tpm2.CurveNISTP224)},
		{"ECC-P256", getECCTemplate(tpm2.CurveNISTP256)},
		{"ECC-P384", getECCTemplate(tpm2.CurveNISTP384)},
		{"ECC-P521", getECCTemplate(tpm2.CurveNISTP521)},
	}
	for _, k := range keys {
		t.Run(k.name, func(t *testing.T) {
			ek, err := client.NewKey(rwc, tpm2.HandleEndorsement, k.template)
			if err != nil {
				t.Fatal(err)
			}
			defer ek.Close()
			pub := ek.PublicKey()
			secret := []byte("super secret code")
			blob, err := CreateImportBlob(pub, secret, nil)
			if err != nil {
				t.Fatalf("creating import blob failed: %v", err)
			}

			output, err := ek.Import(blob)
			if err != nil {
				t.Fatalf("import failed: %v", err)
			}
			if !bytes.Equal(output, secret) {
				t.Errorf("got %X, expected %X", output, secret)
			}
		})
	}
}

func isExpectedError(err error, expected []error) bool {
	for _, candidate := range expected {
		if errors.Is(err, candidate) {
			return true
		}
	}
	return false
}

func TestBadImport(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	valueErr := tpm2.ParameterError{
		Code:      tpm2.RCValue,
		Parameter: tpm2.RC4,
	}
	// RSA keys lengths are not consistent, so we could also get RCSize
	rsaWrongKeyErrs := []error{valueErr, tpm2.ParameterError{
		Code:      tpm2.RCSize,
		Parameter: tpm2.RC4,
	}}
	integrityErr := tpm2.ParameterError{
		Code:      tpm2.RCIntegrity,
		Parameter: tpm2.RC3,
	}
	pointErr := tpm2.ParameterError{
		Code:      tpm2.RCECCPoint,
		Parameter: tpm2.RC4,
	}

	keys := []struct {
		name          string
		template      tpm2.Public
		wrongKeyErrs  []error
		corruptedErrs []error
	}{
		{"RSA", client.DefaultEKTemplateRSA(), rsaWrongKeyErrs, []error{valueErr}},
		{"ECC", client.DefaultEKTemplateECC(), []error{integrityErr}, []error{pointErr}},
		{"SRK-RSA", client.SRKTemplateRSA(), rsaWrongKeyErrs, []error{valueErr}},
		{"SRK-ECC", client.SRKTemplateECC(), []error{integrityErr}, []error{pointErr}},
	}

	for _, k := range keys {
		t.Run(k.name, func(t *testing.T) {
			ek, err := client.NewKey(rwc, tpm2.HandleEndorsement, k.template)
			if err != nil {
				t.Fatal(err)
			}
			defer ek.Close()
			pub := ek.PublicKey()

			// Create a second, different key
			template2 := k.template
			template2.Attributes ^= tpm2.FlagNoDA
			ek2, err := client.NewKey(rwc, tpm2.HandleEndorsement, template2)
			if err != nil {
				t.Fatal(err)
			}
			defer ek2.Close()

			secret := []byte("super secret code")
			blob, err := CreateImportBlob(pub, secret, nil)
			if err != nil {
				t.Fatalf("creating import blob failed: %v", err)
			}

			// Try to import this blob under the wrong key
			if _, err = ek2.Import(blob); !isExpectedError(err, k.wrongKeyErrs) {
				t.Errorf("got error: %v, expected: %v", err, k.wrongKeyErrs)
			}

			// Try to import a corrupted blob
			blob.EncryptedSeed[10] ^= 0xFF
			if _, err = ek.Import(blob); !isExpectedError(err, k.corruptedErrs) {
				t.Errorf("got error: %v, expected: %v", err, k.corruptedErrs)
			}
		})
	}
}

func TestImportPCRs(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		t.Fatal(err)
	}
	defer ek.Close()
	pcr0, err := tpm2.ReadPCR(rwc, 0, tpm2.AlgSHA256)
	if err != nil {
		t.Fatal(err)
	}
	badPCR := append([]byte(nil), pcr0...)
	// badPCR increments first value so it doesn't match.
	badPCR[0]++
	subtests := []struct {
		name          string
		pcrs          *pb.PCRs
		expectSuccess bool
	}{
		{"No-PCR-nil", nil, true},
		{"No-PCR-empty", &pb.PCRs{Hash: pb.HashAlgo_SHA256}, true},
		{"Good-PCR", &pb.PCRs{Hash: pb.HashAlgo_SHA256, Pcrs: map[uint32][]byte{0: pcr0}}, true},
		{"Bad-PCR", &pb.PCRs{Hash: pb.HashAlgo_SHA256, Pcrs: map[uint32][]byte{0: badPCR}}, false},
	}
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			secret := []byte("super secret code")
			blob, err := CreateImportBlob(ek.PublicKey(), secret, subtest.pcrs)
			if err != nil {
				t.Fatalf("creating import blob failed: %v", err)
			}
			output, err := ek.Import(blob)
			if subtest.expectSuccess {
				if err != nil {
					t.Fatalf("import failed: %v", err)
				}
				if !bytes.Equal(output, secret) {
					t.Errorf("got %X, expected %X", output, secret)
				}
			} else if err == nil {
				t.Error("expected Import to fail but it did not")
			}
		})
	}
}

func TestSigningKeyImport(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		t.Fatal(err)
	}
	defer ek.Close()
	signingKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pcr0, err := tpm2.ReadPCR(rwc, 0, tpm2.AlgSHA256)
	if err != nil {
		t.Fatal(err)
	}
	badPCR := append(make([]byte, 0), pcr0...)
	// badPCR increments first value so it doesn't match.
	badPCR[0]++
	subtests := []struct {
		name          string
		pcrs          *pb.PCRs
		expectSuccess bool
	}{
		{"No-PCR-nil", nil, true},
		{"No-PCR-empty", &pb.PCRs{Hash: pb.HashAlgo_SHA256}, true},
		{"Good-PCR", &pb.PCRs{Hash: pb.HashAlgo_SHA256, Pcrs: map[uint32][]byte{0: pcr0}}, true},
		{"Bad-PCR", &pb.PCRs{Hash: pb.HashAlgo_SHA256, Pcrs: map[uint32][]byte{0: badPCR}}, false},
	}
	for _, subtest := range subtests {
		t.Run(subtest.name, func(t *testing.T) {
			blob, err := CreateSigningKeyImportBlob(ek.PublicKey(), signingKey, subtest.pcrs)
			if err != nil {
				t.Fatalf("creating import blob failed: %v", err)
			}

			importedKey, err := ek.ImportSigningKey(blob)
			if err != nil {
				t.Fatalf("import failed: %v", err)
			}
			defer importedKey.Close()
			signer, err := importedKey.GetSigner()
			if err != nil {
				t.Fatalf("could not create signer: %v", err)
			}
			var digest [32]byte

			sig, err := signer.Sign(nil, digest[:], crypto.SHA256)
			if subtest.expectSuccess {
				if err != nil {
					t.Fatalf("import failed: %v", err)
				}
				if err = rsa.VerifyPKCS1v15(&signingKey.PublicKey, crypto.SHA256, digest[:], sig); err != nil {
					t.Error(err)
				}
				return
			} else if err == nil {
				t.Error("expected Import to fail but it did not")
			}
		})
	}
}
