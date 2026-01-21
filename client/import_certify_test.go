package client_test

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	tpb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpm2/transport"
)

func TestCreateCertifiedAKBlob(t *testing.T) {
	rwc := test.GetTPM(t)
	tpm := transport.FromReadWriter(rwc)
	defer client.CheckedClose(t, rwc)

	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		t.Fatalf("failed to get rsa ek: %v", ek)
	}
	defer ek.Close()

	pubBytes, err := ek.PublicArea().Encode()
	if err != nil {
		t.Fatalf("ek public area encode failed: %v", err)
	}
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](pubBytes)
	if err != nil {
		t.Fatalf("Unmarshal public key failed: %v", err)
	}

	testcases := []struct {
		name    string
		keyAlgo tpm2.TPMAlgID
	}{
		{"RSA", tpm2.TPMAlgRSA},
		{"ECC", tpm2.TPMAlgECC},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			challenge, secret, err := server.CreateRestrictedHMACBlob(pub)
			if err != nil {
				t.Fatalf("server.CreateChallenge failed: %v", err)
			}

			response, err := client.CreateCertifiedAKBlob(tpm, challenge, tc.keyAlgo)
			if err != nil {
				t.Fatalf("SolveChallengeImportCertify failed: %v", err)
			}
			if err := server.VerifyCertifiedAKBlob(response, secret); err != nil {
				t.Errorf("server.VerifyCertifiedAKBlob failed: %v", err)
			}
		})
	}
}

func TestVerifyCertifiedAKBlobErrors(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	tpm := transport.FromReadWriter(rwc)

	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		t.Fatalf("failed to get rsa ek: %v", ek)
	}
	defer ek.Close()

	pubBytes, err := ek.PublicArea().Encode()
	if err != nil {
		t.Fatalf("ek public area encode failed: %v", err)
	}
	ekPub, err := tpm2.Unmarshal[tpm2.TPMTPublic](pubBytes)
	if err != nil {
		t.Fatalf("Unmarshal public key failed: %v", err)
	}
	challenge, secret, err := server.CreateRestrictedHMACBlob(ekPub)
	if err != nil {
		t.Fatalf("server.CreateChallenge failed: %v", err)
	}

	response, err := client.CreateCertifiedAKBlob(tpm, challenge, tpm2.TPMAlgECC)
	if err != nil {
		t.Fatalf("SolveChallengeImportCertify failed: %v", err)
	}

	// Make a copy of the valid data to tamper with
	goodAkPub := bytes.Clone(response.GetPubArea())
	goodCertifyInfo := bytes.Clone(response.GetCertifyInfo())
	goodSignature := bytes.Clone(response.GetRawSig())

	// helper to re-sign a modified certifyInfo
	reSign := func(certifyInfo []byte) []byte {
		sig, err := tpm2.Unmarshal[tpm2.TPMTSignature](goodSignature)
		if err != nil {
			t.Fatalf("unmarshaling good signature: %v", err)
		}
		hmacVal, err := sig.Signature.HMAC()
		if err != nil {
			t.Fatalf("getting hmac from signature: %v", err)
		}
		digest := sha256.Sum256(certifyInfo)
		h := hmac.New(sha256.New, secret)
		h.Write(digest[:])
		hmacVal.Digest = h.Sum(nil)
		return tpm2.Marshal(sig)
	}

	testcases := []struct {
		name          string
		getReq        func(t *testing.T) *tpb.CertifiedBlob
		secret        []byte
		wantErrString string
	}{
		{
			name: "Bad Secret",
			getReq: func(_ *testing.T) *tpb.CertifiedBlob {
				return response
			},
			secret:        []byte("bad secret"),
			wantErrString: "invalid HMAC",
		},
		{
			name: "Wrong HMAC Hash Alg",
			getReq: func(t *testing.T) *tpb.CertifiedBlob {
				sig, err := tpm2.Unmarshal[tpm2.TPMTSignature](goodSignature)
				if err != nil {
					t.Fatalf("unmarshaling good signature: %v", err)
				}
				hmacVal, err := sig.Signature.HMAC()
				if err != nil {
					t.Fatalf("getting hmac from signature: %v", err)
				}
				hmacVal.HashAlg = tpm2.TPMAlgSHA1
				return &tpb.CertifiedBlob{
					PubArea:     goodAkPub,
					CertifyInfo: goodCertifyInfo,
					RawSig:      tpm2.Marshal(sig),
				}
			},
			secret:        secret,
			wantErrString: "wrong hash algorithm",
		},
		{
			name: "Bad HMAC Digest",
			getReq: func(t *testing.T) *tpb.CertifiedBlob {
				sig, err := tpm2.Unmarshal[tpm2.TPMTSignature](goodSignature)
				if err != nil {
					t.Fatalf("unmarshaling good signature: %v", err)
				}
				hmacVal, err := sig.Signature.HMAC()
				if err != nil {
					t.Fatalf("getting hmac from signature: %v", err)
				}
				hmacVal.Digest[0] ^= 0xff
				return &tpb.CertifiedBlob{
					PubArea:     goodAkPub,
					CertifyInfo: goodCertifyInfo,
					RawSig:      tpm2.Marshal(sig),
				}
			},
			secret:        secret,
			wantErrString: "invalid HMAC",
		},
		{
			name: "Tampered CertifyInfo",
			getReq: func(_ *testing.T) *tpb.CertifiedBlob {
				badCertifyInfo := bytes.Clone(goodCertifyInfo)
				badCertifyInfo[0] ^= 0xff
				return &tpb.CertifiedBlob{
					PubArea:     goodAkPub,
					CertifyInfo: badCertifyInfo,
					RawSig:      goodSignature,
				}
			},
			secret:        secret,
			wantErrString: "invalid HMAC",
		},
		{
			name: "Bad Attest Magic",
			getReq: func(t *testing.T) *tpb.CertifiedBlob {
				attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](goodCertifyInfo)
				if err != nil {
					t.Fatalf("unmarshaling good certify info: %v", err)
				}
				attest.Magic = 0
				badCertifyInfo := tpm2.Marshal(attest)
				return &tpb.CertifiedBlob{
					PubArea:     goodAkPub,
					CertifyInfo: badCertifyInfo,
					RawSig:      reSign(badCertifyInfo),
				}
			},
			secret:        secret,
			wantErrString: "attestation statement was invalid",
		},
		{
			name: "Bad Certified Name",
			getReq: func(t *testing.T) *tpb.CertifiedBlob {
				attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](goodCertifyInfo)
				if err != nil {
					t.Fatalf("unmarshaling good certify info: %v", err)
				}
				certify, err := attest.Attested.Certify()
				if err != nil {
					t.Fatalf("getting certify from attest: %v", err)
				}
				certify.Name.Buffer[0] ^= 0xff
				badCertifyInfo := tpm2.Marshal(attest)

				return &tpb.CertifiedBlob{
					PubArea:     goodAkPub,
					CertifyInfo: badCertifyInfo,
					RawSig:      reSign(badCertifyInfo),
				}
			},
			secret:        secret,
			wantErrString: "incorrect name",
		},
		{
			name: "QualifiedName matches Name",
			getReq: func(t *testing.T) *tpb.CertifiedBlob {
				attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](goodCertifyInfo)
				if err != nil {
					t.Fatalf("unmarshaling good certify info: %v", err)
				}
				certify, err := attest.Attested.Certify()
				if err != nil {
					t.Fatalf("getting certify from attest: %v", err)
				}
				certify.QualifiedName.Buffer = bytes.Clone(certify.Name.Buffer)
				badCertifyInfo := tpm2.Marshal(attest)
				return &tpb.CertifiedBlob{
					PubArea:     goodAkPub,
					CertifyInfo: badCertifyInfo,
					RawSig:      reSign(badCertifyInfo),
				}
			},
			secret:        secret,
			wantErrString: "incorrect name",
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			err := server.VerifyCertifiedAKBlob(tc.getReq(t), tc.secret)
			if err == nil || !strings.Contains(err.Error(), tc.wantErrString) {
				t.Errorf("got err: %v, want err containing: %q", err, tc.wantErrString)
			}
		})
	}
}
