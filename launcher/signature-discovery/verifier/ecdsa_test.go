package verifier

import (
	"crypto"
	"encoding/base64"
	"strings"
	"testing"

	utils "github.com/google/go-tpm-tools/launcher/signature-discovery"
	"github.com/google/go-tpm-tools/launcher/signature-discovery/oci"
)

// Generate a ECDSA public key by following these steps:
// 1. Generate a ECDSA private key using:
// openssl ecparam -name prime256v1 -genkey -noout -out private.pem
// 2. Extract from the private key using:
// openssl ec -in private.pem -pubout -out public.pem
const ecdsaPubKey = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEMLdxI5u7ON+1QzJ+njeahioIRU/V
gqLf36SUAhbJ/Qnof5HkiJfXB/cBawuddv9JfNFL4nXLNZTHfz4uBrPduw==
-----END PUBLIC KEY-----`

func TestECDSAVerifySignatureSuccess(t *testing.T) {
	verifier, err := loadVerifier(oci.EcdsaP256Sha256)
	if err != nil {
		t.Fatalf("unalbe to load a ECDSA_P256_SHA256 verifier")
	}
	payload := []byte("hello world!")

	// base64-encoded signature generated with:
	// openssl dgst -sign private.pem -sha256 | base64
	signature := "MEYCIQDl0nmdnkMBZc5rLmMR3cWOcZbXcBiNyCdhctKN+RpqHAIhALiaSW8gdCiBjxmXNWF8BBKAVu24u9JisY6juSfYbcNF"
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatalf("unable to decode base64 encoded signature: %v", err)
	}
	pub, err := utils.UnmarshalPEMToPub([]byte(ecdsaPubKey))
	if err != nil {
		t.Fatalf("unable to parse a PEM encoded public key: %v", err)
	}
	if err := verifier.VerifySignature(payload, sigBytes, pub); err != nil {
		t.Errorf("invalid ECDSA_P256_SHA256 signature: %v", err)
	}
}

func TestECDSAVerifySignatureFailedCases(t *testing.T) {
	mismatchedPubKey := `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEjzUXn0HNOwGfmR/EwrMb59sb+zRX
TSpMYm8DiHgBlQuUIuchvO4F2IrweKJjc0hh7eEn9NdCegVey/namk9cEA==
-----END PUBLIC KEY-----`

	testCases := []struct {
		name      string
		hashFunc  crypto.Hash
		payload   []byte
		signature string
		pubKey    string
		wantErr   string
	}{
		{
			name:      "VerifySignature failed with invalid payload",
			hashFunc:  crypto.SHA256,
			payload:   []byte("invalid"),
			signature: "MEYCIQDl0nmdnkMBZc5rLmMR3cWOcZbXcBiNyCdhctKN+RpqHAIhALiaSW8gdCiBjxmXNWF8BBKAVu24u9JisY6juSfYbcNF",
			pubKey:    ecdsaPubKey,
			wantErr:   "invalid ECDSA signature",
		},
		{
			name:      "VerifySiganture failed with unsupported hash function",
			hashFunc:  crypto.MD5,
			payload:   []byte("hello world!"),
			signature: "MEYCIQDl0nmdnkMBZc5rLmMR3cWOcZbXcBiNyCdhctKN+RpqHAIhALiaSW8gdCiBjxmXNWF8BBKAVu24u9JisY6juSfYbcNF",
			pubKey:    ecdsaPubKey,
			wantErr:   "failed to compute digest: invalid hash function specified",
		},
		{
			name:     "VerifySiganture failed with invalid signature",
			hashFunc: crypto.SHA256,
			payload:  []byte("hello world!"),
			// base64-encoded "hello world"
			signature: "aGVsbG8gd29ybGQ=",
			pubKey:    ecdsaPubKey,
			wantErr:   "invalid ECDSA signature",
		},
		{
			name:      "VerifySignature failed with mismatched public key",
			hashFunc:  crypto.SHA256,
			payload:   []byte("hello world!"),
			signature: "MEYCIQDl0nmdnkMBZc5rLmMR3cWOcZbXcBiNyCdhctKN+RpqHAIhALiaSW8gdCiBjxmXNWF8BBKAVu24u9JisY6juSfYbcNF",
			pubKey:    mismatchedPubKey,
			wantErr:   "invalid ECDSA signature",
		},
		{
			name:      "VerifySignature failed with RSA public key",
			hashFunc:  crypto.SHA256,
			payload:   []byte("hello world!"),
			signature: "MEYCIQDl0nmdnkMBZc5rLmMR3cWOcZbXcBiNyCdhctKN+RpqHAIhALiaSW8gdCiBjxmXNWF8BBKAVu24u9JisY6juSfYbcNF",
			pubKey:    rsaPubKey,
			wantErr:   "public key is not an ECDSA public key",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			verifier := &ECDSAVerifier{hashFunc: tc.hashFunc}
			sigBytes, err := base64.StdEncoding.DecodeString(tc.signature)
			if err != nil {
				t.Fatalf("unable to decode base64 encoded signature: %v", err)
			}
			pub, err := utils.UnmarshalPEMToPub([]byte(tc.pubKey))
			if err != nil {
				t.Fatalf("unable to parse a PEM encoded public key: %v", err)
			}
			if err := verifier.VerifySignature(tc.payload, sigBytes, pub); !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("VerifySignature() failed for testcase %s: got error [%v], but want error [%v]", tc.name, err.Error(), tc.wantErr)
			}
		})
	}
}
