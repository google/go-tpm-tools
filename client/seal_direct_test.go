package client

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"github.com/google/go-tpm-tools/internal/test"
	"github.com/google/go-tpm/direct/structures/tpm"
	"github.com/google/go-tpm/direct/structures/tpml"
	"github.com/google/go-tpm/direct/structures/tpms"
	"github.com/google/go-tpm/direct/structures/tpmt"
	tpm2direct "github.com/google/go-tpm/direct/tpm2"
)

func CreatePCRSelection(s []int) ([]byte, error) {
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

func TestLegacySealDirectUnseal(t *testing.T) {
	rwc := test.GetTPM(t)
	defer CheckedClose(t, rwc)

	keys := []struct {
		name   string
		getSRK func(io.ReadWriter) (*Key, error)
	}{
		{"RSA", StorageRootKeyRSA},
		{"ECC", StorageRootKeyECC},
	}

	for _, key := range keys {
		t.Run(key.name, func(t *testing.T) {
			srk, err := key.getSRK(rwc)
			if err != nil {
				t.Fatalf("can't create %s srk from template: %v", key.name, err)
			}
			defer srk.Close()

			secret := []byte("test")
			pcrToChange := test.DebugPCR

			// Sealing with the Legacy
			sel := tpm2.PCRSelection{Hash: tpm2.AlgSHA256, PCRs: []int{7, pcrToChange}}
			sealed, err := srk.Seal(secret, SealOpts{Current: sel})
			if err != nil {
				t.Fatalf("failed to seal: %v", err)
			}

			// Unsealing with the Direct
			PCR7, err := CreatePCRSelection([]int{7})
			if err != nil {
				t.Fatalf("Failed to create PCRSelection")
			}

			unsealOpts := unsealOptsDirect{
				CertifyCurrent: tpms.PCRSelection{
					Hash:      tpm.AlgSHA256,
					PCRSelect: PCR7,
				},
			}
			unseal, err := srk.unsealDirect(sealed, unsealOpts)
			if err != nil {
				t.Fatalf("failed to unseal: %v", err)
			}

			if !bytes.Equal(secret, unseal) {
				t.Fatalf("unsealed (%v) not equal to secret (%v)", unseal, secret)
			}

			extension := bytes.Repeat([]byte{0xAA}, sha256.Size)
			pcrExtend := tpm2direct.PCRExtend{
				PCRHandle: tpm.Handle(pcrToChange),
				Digests: tpml.DigestValues{
					Digests: []tpmt.HA{
						{
							HashAlg: tpm.AlgSHA256,
							Digest:  extension,
						},
					},
				},
			}
			if err := pcrExtend.Execute(srk.transportTPM()); err != nil {
				t.Fatalf("failed to extend pcr for test %v", err)
			}

			// unseal should not succeed.
			if _, err = srk.unsealDirect(sealed, unsealOpts); err == nil {
				t.Fatalf("unseal should have caused an error: %v", err)
			}
		})
	}
}

func TestDirectSealLegacyUnseal(t *testing.T) {
	rwc := test.GetTPM(t)
	defer CheckedClose(t, rwc)

	keys := []struct {
		name   string
		getSRK func(io.ReadWriter) (*Key, error)
	}{
		{"RSA", StorageRootKeyRSA},
		{"ECC", StorageRootKeyECC},
	}

	for _, key := range keys {
		t.Run(key.name, func(t *testing.T) {
			srk, err := key.getSRK(rwc)
			if err != nil {
				t.Fatalf("can't create %s srk from template: %v", key.name, err)
			}
			defer srk.Close()

			secret := []byte("test")
			pcrToChange := test.DebugPCR

			// Sealing with the Direct
			sel, err := CreatePCRSelection([]int{7, pcrToChange})
			if err != nil {
				t.Fatalf("Failed to create PCRSelection")
			}

			sealOpts := sealOptsDirect{
				Current: tpms.PCRSelection{
					Hash:      tpm.AlgSHA256,
					PCRSelect: sel,
				},
			}
			sealed, err := srk.sealDirect(secret, sealOpts)
			if err != nil {
				t.Fatalf("failed to seal: %v", err)
			}

			// Unsealing with the Legacy
			opts := UnsealOpts{
				CertifyCurrent: tpm2.PCRSelection{
					Hash: tpm2.AlgSHA256,
					PCRs: []int{7},
				},
			}
			unseal, err := srk.Unseal(sealed, opts)
			if err != nil {
				t.Fatalf("failed to unseal: %v", err)
			}
			if !bytes.Equal(secret, unseal) {
				t.Fatalf("unsealed (%v) not equal to secret (%v)", unseal, secret)
			}

			extension := bytes.Repeat([]byte{0xAA}, sha256.Size)
			if err = tpm2.PCRExtend(rwc, tpmutil.Handle(pcrToChange), tpm2.AlgSHA256, extension, ""); err != nil {
				t.Fatalf("failed to extend pcr: %v", err)
			}

			// unseal should not succeed.
			if _, err = srk.Unseal(sealed, opts); err == nil {
				t.Fatalf("unseal should have caused an error: %v", err)
			}
		})
	}
}

func TestDirectSealDirectUnseal(t *testing.T) {
	rwc := test.GetTPM(t)
	defer CheckedClose(t, rwc)

	keys := []struct {
		name   string
		getSRK func(io.ReadWriter) (*Key, error)
	}{
		{"RSA", StorageRootKeyRSA},
		{"ECC", StorageRootKeyECC},
	}

	for _, key := range keys {
		t.Run(key.name, func(t *testing.T) {
			srk, err := key.getSRK(rwc)
			if err != nil {
				t.Fatalf("can't create %s srk from template: %v", key.name, err)
			}
			defer srk.Close()

			secret := []byte("test")
			pcrToChange := test.DebugPCR

			// Sealing with the Direct
			sel, err := CreatePCRSelection([]int{7, pcrToChange})
			if err != nil {
				t.Fatalf("Failed to create PCRSelection")
			}

			sealOpts := sealOptsDirect{
				Current: tpms.PCRSelection{
					Hash:      tpm.AlgSHA256,
					PCRSelect: sel,
				},
			}
			sealed, err := srk.sealDirect(secret, sealOpts)
			if err != nil {
				t.Fatalf("failed to seal: %v", err)
			}

			// Unsealing with the Direct
			PCR7, err := CreatePCRSelection([]int{7})
			if err != nil {
				t.Fatalf("Failed to create PCRSelection")
			}

			unsealOpts := unsealOptsDirect{
				CertifyCurrent: tpms.PCRSelection{
					Hash:      tpm.AlgSHA256,
					PCRSelect: PCR7,
				},
			}
			unseal, err := srk.unsealDirect(sealed, unsealOpts)
			if err != nil {
				t.Fatalf("failed to unseal: %v", err)
			}

			if !bytes.Equal(secret, unseal) {
				t.Fatalf("unsealed (%v) not equal to secret (%v)", unseal, secret)
			}

			extension := bytes.Repeat([]byte{0xAA}, sha256.Size)
			pcrExtend := tpm2direct.PCRExtend{
				PCRHandle: tpm.Handle(pcrToChange),
				Digests: tpml.DigestValues{
					Digests: []tpmt.HA{
						{
							HashAlg: tpm.AlgSHA256,
							Digest:  extension,
						},
					},
				},
			}
			if err := pcrExtend.Execute(srk.transportTPM()); err != nil {
				t.Fatalf("failed to extend pcr for test %v", err)
			}

			// unseal should not succeed.
			if _, err = srk.unsealDirect(sealed, unsealOpts); err == nil {
				t.Fatalf("unseal should have caused an error: %v", err)
			}

		})
	}
}
