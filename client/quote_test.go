package client_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal"
	"github.com/google/go-tpm/tpm2"
)

func TestQuote(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	keys := []struct {
		name   string
		getKey func(io.ReadWriter) (*client.Key, error)
	}{
		{"AK-ECC", client.AttestationKeyECC},
		{"AK-RSA", client.AttestationKeyRSA},
	}

	pcrSels := []tpm2.PCRSelection{
		{
			Hash: tpm2.AlgSHA256,
			PCRs: []int{7},
		},
		client.FullPcrSel(tpm2.AlgSHA256),
	}

	for _, key := range keys {
		for _, sel := range pcrSels {
			name := fmt.Sprintf("%s-%d", key.name, len(sel.PCRs))
			t.Run(name, func(t *testing.T) {
				ak, err := key.getKey(rwc)
				if err != nil {
					t.Errorf("failed to generate AK: %v", err)
				}
				defer ak.Close()

				quoted, err := ak.Quote(sel, []byte("test"))
				if err != nil {
					t.Errorf("failed to quote: %v", err)
				}
				sig, err := tpm2.DecodeSignature(bytes.NewBuffer(quoted.GetRawSig()))
				if err != nil {
					t.Errorf("signature decoding failed: %v", err)
				}

				switch pub := ak.PublicKey().(type) {
				case *ecdsa.PublicKey:
					hash, err := sig.ECC.HashAlg.Hash()
					if err != nil {
						t.Fatalf("not a valid hash type: %v", sig.ECC.HashAlg)
					}

					hashCon := hash.New()
					hashCon.Write(quoted.GetQuote())
					if !ecdsa.Verify(pub, hashCon.Sum(nil)[:], sig.ECC.R, sig.ECC.S) {
						t.Errorf("ECC signature verification failed")
					}
				case *rsa.PublicKey:
					hash, err := sig.RSA.HashAlg.Hash()
					if err != nil {
						t.Fatalf("not a valid hash type: %v", sig.RSA.HashAlg)
					}

					hashCon := hash.New()
					hashCon.Write(quoted.GetQuote())
					if err = rsa.VerifyPKCS1v15(pub, hash, hashCon.Sum(nil), []byte(sig.RSA.Signature)); err != nil {
						t.Errorf("RSA signature verification failed: %v", err)
					}
				}
			})
		}
	}

}

func TestQuoteShouldFailWithNonSigningKey(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	srk, err := client.StorageRootKeyRSA(rwc)
	if err != nil {
		t.Errorf("failed to generate SRK: %v", err)
	}
	defer srk.Close()

	selpcr := tpm2.PCRSelection{
		Hash: tpm2.AlgSHA1,
		PCRs: []int{7},
	}
	_, err = srk.Quote(selpcr, []byte("test"))
	if err == nil {
		t.Errorf("Quote with a non-signing key should fail")
	}
	t.Log(err)
}
