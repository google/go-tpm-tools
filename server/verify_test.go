package server

import (
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

func getDigestHash(input string) []byte {
	inputDigestHash := sha256.New()
	inputDigestHash.Write([]byte(input))
	return inputDigestHash.Sum(nil)
}

func extendPCRsRandomly(rwc io.ReadWriteCloser, selpcr tpm2.PCRSelection) error {
	var pcrExtendValue []byte
	if selpcr.Hash == tpm2.AlgSHA256 {
		pcrExtendValue = make([]byte, 32)
	} else if selpcr.Hash == tpm2.AlgSHA1 {
		pcrExtendValue = make([]byte, 20)
	}

	for _, v := range selpcr.PCRs {
		_, err := rand.Read(pcrExtendValue)
		if err != nil {
			return fmt.Errorf("random bytes read fail %v", err)
		}
		err = tpm2.PCRExtend(rwc, tpmutil.Handle(int(v)), selpcr.Hash, pcrExtendValue, "")
		if err != nil {
			return fmt.Errorf("PCR extend fail %v", err)
		}
	}
	return nil
}

func TestVerifyHappyCases(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	tests := []struct {
		name         string
		getKey       func(io.ReadWriter) (*client.Key, error)
		pcrHashAlgo  tpm2.Algorithm
		quotePCRList []int
		extraData    []byte
	}{
		{"AK-RSA_SHA1_2PCRs_nonce", client.AttestationKeyRSA, tpm2.AlgSHA1, []int{7, 6}, getDigestHash("test")},
		{"AK-RSA_SHA1_1PCR_nonce", client.AttestationKeyRSA, tpm2.AlgSHA1, []int{7}, getDigestHash("t")},
		{"AK-RSA_SHA1_1PCR_no-nonce", client.AttestationKeyRSA, tpm2.AlgSHA1, []int{7}, nil},
		{"AK-RSA_SHA256_2PCRs_nonce", client.AttestationKeyRSA, tpm2.AlgSHA256, []int{7, 6}, getDigestHash("test")},
		{"AK-RSA_SHA256_3PCR_no-nonce", client.AttestationKeyRSA, tpm2.AlgSHA256, []int{7, 6, 5}, nil},
		{"AK-RSA_SHA256_4PCR_empty-nonce", client.AttestationKeyRSA, tpm2.AlgSHA256, []int{7, 6, 5, 4}, []byte{}},
		{"AK-RSA_SHA256_dupePCrSel_nonce", client.AttestationKeyRSA, tpm2.AlgSHA256, []int{7, 6, 6, 6, 1}, getDigestHash("")},

		{"AK-ECC_SHA1_2PCRs_nonce", client.AttestationKeyECC, tpm2.AlgSHA1, []int{7, 6}, getDigestHash("test")},
		{"AK-ECC_SHA1_1PCR_nonce", client.AttestationKeyECC, tpm2.AlgSHA1, []int{7}, getDigestHash("t")},
		{"AK-ECC_SHA1_1PCR_no-nonce", client.AttestationKeyECC, tpm2.AlgSHA1, []int{7}, nil},
		{"AK-ECC_SHA256_2PCRs_nonce", client.AttestationKeyECC, tpm2.AlgSHA256, []int{7, 6}, getDigestHash("test")},
		{"AK-ECC_SHA256_3PCR_no-nonce", client.AttestationKeyECC, tpm2.AlgSHA256, []int{7, 6, 5}, nil},
		{"AK-ECC_SHA256_4PCR_empty-nonce", client.AttestationKeyECC, tpm2.AlgSHA256, []int{7, 6, 5, 4}, []byte{}},
		{"AK-ECC_SHA256_dupePCrSel_nonce", client.AttestationKeyECC, tpm2.AlgSHA256, []int{7, 6, 6, 6, 1}, getDigestHash("")},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ak, err := test.getKey(rwc)
			if err != nil {
				t.Errorf("failed to generate AK: %v", err)
			}
			defer ak.Close()

			selpcr := tpm2.PCRSelection{
				Hash: test.pcrHashAlgo,
				PCRs: test.quotePCRList,
			}
			err = extendPCRsRandomly(rwc, selpcr)
			if err != nil {
				t.Fatalf("failed to extend test PCRs: %v", err)
			}
			quoted, err := ak.Quote(selpcr, test.extraData)
			if err != nil {
				t.Fatalf("failed to quote: %v", err)
			}
			err = quoted.Verify(ak.PublicKey(), test.extraData)
			if err != nil {
				t.Fatalf("failed to verify: %v", err)
			}
		})
	}
}

func TestVerifyPCRChanged(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		t.Errorf("failed to generate AK: %v", err)
	}
	defer ak.Close()

	selpcr := tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: []int{7},
	}
	err = extendPCRsRandomly(rwc, selpcr)
	if err != nil {
		t.Errorf("failed to extend test PCRs: %v", err)
	}
	nonce := getDigestHash("test")
	quoted, err := ak.Quote(selpcr, nonce)
	if err != nil {
		t.Error(err)
	}

	// change the PCR 7 value
	err = extendPCRsRandomly(rwc, selpcr)
	if err != nil {
		t.Errorf("failed to extend test PCRs: %v", err)
	}

	quoted.Pcrs, err = client.ReadPCRs(rwc, selpcr)
	if err != nil {
		t.Errorf("failed to read PCRs: %v", err)
	}
	err = quoted.Verify(ak.PublicKey(), nonce)
	if err == nil {
		t.Errorf("Verify should fail as Verify read a modified PCR")
	}
}

func TestVerifyUsingDifferentPCR(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		t.Errorf("failed to generate AK: %v", err)
	}
	defer ak.Close()

	err = extendPCRsRandomly(rwc, tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: []int{7, 8},
	})
	if err != nil {
		t.Errorf("failed to extend test PCRs: %v", err)
	}

	nonce := getDigestHash("test")
	quoted, err := ak.Quote(tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: []int{7},
	}, nonce)
	if err != nil {
		t.Error(err)
	}

	quoted.Pcrs, err = client.ReadPCRs(rwc, tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: []int{8},
	})
	if err != nil {
		t.Errorf("failed to read PCRs: %v", err)
	}
	err = quoted.Verify(ak.PublicKey(), nonce)
	if err == nil {
		t.Errorf("Verify should fail as Verify read a different PCR")
	}
}
