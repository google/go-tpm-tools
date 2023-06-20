package client_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"io"
	"testing"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	"github.com/google/go-tpm/legacy/tpm2"
)

func TestQuote(t *testing.T) {
	rwc := test.GetTPM(t)
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
	rwc := test.GetTPM(t)
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

// Basic tests of Key.Attest, more advanced methods are in server package
func TestAttest(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	keys := []struct {
		name          string
		getKey        func(io.ReadWriter) (*client.Key, error)
		shouldSucceed bool
	}{
		{"AK-ECC", client.AttestationKeyECC, true},
		{"AK-RSA", client.AttestationKeyRSA, true},
		{"EK-ECC", client.EndorsementKeyECC, false},
		{"EK-RSA", client.EndorsementKeyRSA, false},
	}
	for _, key := range keys {
		t.Run(key.name, func(t *testing.T) {
			ak, err := key.getKey(rwc)
			if err != nil {
				t.Fatalf("failed to generate AK: %v", err)
			}
			defer ak.Close()

			attestation, err := ak.Attest(client.AttestOpts{Nonce: []byte("some nonce")})
			if !key.shouldSucceed {
				if err == nil {
					t.Error("expected failure when calling Attest")
				}
				return
			}
			if err != nil {
				t.Fatalf("failed to attest: %v", err)
			}

			// Basic check, make sure we got multiple banks, and fields parse
			if _, err = tpm2.DecodePublic(attestation.AkPub); err != nil {
				t.Errorf("failed to decode AkPub: %v", err)
			}
			if len(attestation.Quotes) <= 1 {
				t.Error("expected multiple quotes")
			}
			if _, err = attest.ParseEventLog(attestation.EventLog); err != nil {
				t.Errorf("failed to parse event log: %v", err)
			}
		})

	}
}
