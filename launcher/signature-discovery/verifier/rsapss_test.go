package verifier

import (
	"crypto"
	"encoding/base64"
	"strings"
	"testing"

	utils "github.com/google/go-tpm-tools/launcher/signature-discovery"
	"github.com/google/go-tpm-tools/launcher/signature-discovery/oci"
)

// Generate a RSA public key by following these steps:
// 1. Generate a RSA private key using:
// openssl genrsa -out private.pem 1024
// 2. Extract from the private key using:
// openssl rsa -in private.pem -pubout -out public.pem
const rsaPubKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCtemyHhL06qq6WI7WRuS1OGINn
r8UC3Ee2khu8YcMMl1WrSlQcou1Xa2/iTeWHNDQu+bMuEhoIQfC8KW5W+4e3mA4X
kvqe3gcTFdN9Vnsp3tW260MKE7OEmBEdOJ9guTI7oIejj8MW0J0qJJnPhBGmjve7
TuK6bgn9+KDX3bq8KwIDAQAB
-----END PUBLIC KEY-----`

func TestRSAPSSVerifySignatureSuccess(t *testing.T) {
	verifier, err := loadVerifier(oci.RsassaPssSha256)
	if err != nil {
		t.Fatalf("unalbe to load a RSASSA_PSS_SHA256 verifier")
	}
	payload := []byte("hello world!")

	// base64-encoded signature generated with:
	// openssl dgst -sign private.pem -sigopt rsa_padding_mode:pss -sha256 | base64
	signature := "P1E84UGefgZoEwUGlVRmUNLXOraMcYtlN13MwnA8KGpPeYSEEQ+j+vCHhAKXM2PJ+pkyK2N8ULwHTElYbNa/wRiJnm4vnU5Bchv8FsLNUoFtdueYsPnYFuyRO141uvCo54AlIHATV+un5rfC1p4qlIh0OTMKnnnO/HsmY7G9rmM="
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatalf("unable to decode base64 encoded signature: %v", err)
	}
	pub, err := utils.UnmarshalPEMToPub([]byte(rsaPubKey))
	if err != nil {
		t.Fatalf("unable to parse a PEM encoded public key: %v", err)
	}
	if err := verifier.VerifySignature(payload, sigBytes, pub); err != nil {
		t.Errorf("invalid RSA_PSS_SHA256 signature: %v", err)
	}
}

func TestRSAPSSVerifySignatureFailedCases(t *testing.T) {
	mismatchedPubKey := `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCNEi/TiRoeS29nnSCTGX61+Z/3
6mKZmEoC81cFAYSV5f+K6oR7dwqz14wCJSNleCLLGHYfGSeWIimcfzwK6Ar93RJm
+k1wjGBmAZawd1AkIWRAXW7TzRPbO30xSpcnQ1M1bZTyjXioEDkCuB0DLpHj2gc7
q/hY7zZO8rnRN1xzTwIDAQAB
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
			signature: "P1E84UGefgZoEwUGlVRmUNLXOraMcYtlN13MwnA8KGpPeYSEEQ+j+vCHhAKXM2PJ+pkyK2N8ULwHTElYbNa/wRiJnm4vnU5Bchv8FsLNUoFtdueYsPnYFuyRO141uvCo54AlIHATV+un5rfC1p4qlIh0OTMKnnnO/HsmY7G9rmM=",
			pubKey:    rsaPubKey,
			wantErr:   "verification error",
		},
		{
			name:      "VerifySiganture failed with unsupported hash function",
			hashFunc:  crypto.MD5,
			payload:   []byte("hello world!"),
			signature: "P1E84UGefgZoEwUGlVRmUNLXOraMcYtlN13MwnA8KGpPeYSEEQ+j+vCHhAKXM2PJ+pkyK2N8ULwHTElYbNa/wRiJnm4vnU5Bchv8FsLNUoFtdueYsPnYFuyRO141uvCo54AlIHATV+un5rfC1p4qlIh0OTMKnnnO/HsmY7G9rmM=",
			pubKey:    rsaPubKey,
			wantErr:   "failed to compute digest: invalid hash function specified",
		},
		{
			name:     "VerifySiganture failed with invalid signature",
			hashFunc: crypto.SHA256,
			payload:  []byte("hello world!"),
			// base64-encoded "hello world"
			signature: "aGVsbG8gd29ybGQ=",
			pubKey:    rsaPubKey,
			wantErr:   "verification error",
		},
		{
			name:      "VerifySignature failed with mismatched public key",
			hashFunc:  crypto.SHA256,
			payload:   []byte("hello world!"),
			signature: "P1E84UGefgZoEwUGlVRmUNLXOraMcYtlN13MwnA8KGpPeYSEEQ+j+vCHhAKXM2PJ+pkyK2N8ULwHTElYbNa/wRiJnm4vnU5Bchv8FsLNUoFtdueYsPnYFuyRO141uvCo54AlIHATV+un5rfC1p4qlIh0OTMKnnnO/HsmY7G9rmM=",
			pubKey:    mismatchedPubKey,
			wantErr:   "verification error",
		},
		{
			name:      "VerifySignature failed with ECDSA public key",
			hashFunc:  crypto.SHA256,
			payload:   []byte("hello world!"),
			signature: "P1E84UGefgZoEwUGlVRmUNLXOraMcYtlN13MwnA8KGpPeYSEEQ+j+vCHhAKXM2PJ+pkyK2N8ULwHTElYbNa/wRiJnm4vnU5Bchv8FsLNUoFtdueYsPnYFuyRO141uvCo54AlIHATV+un5rfC1p4qlIh0OTMKnnnO/HsmY7G9rmM=",
			pubKey:    ecdsaPubKey,
			wantErr:   "public key is not a rsa public key",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			verifier := &RSAPSSVerifier{hashFunc: tc.hashFunc}
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
