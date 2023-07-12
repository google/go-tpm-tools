package verifier

import (
	"crypto"
	"encoding/base64"
	"strings"
	"testing"

	utils "github.com/google/go-tpm-tools/launcher/signature-discovery"
	"github.com/google/go-tpm-tools/launcher/signature-discovery/oci"
)

func TestRSAPKCS1V15Success(t *testing.T) {
	verifier, err := LoadVerifier(oci.RsassaPkcs1v15Sha256)
	if err != nil {
		t.Fatalf("unalbe to load a RSA_PKCS1V15_SHA256 verifier")
	}
	payload := []byte("hello world!")

	// base64-encoded signature generated with:
	// openssl dgst -sign private.pem -sha256 | base64
	signature := "MNjVDEwKqOTlhSX4q8HW2scapRUfDlqfIa1n7yMg5PlD/sHPrXT1FKf7BDW7ZRYxBS3CMNoEQbonjE8OVU9oEeewi0t1ddfF3FidcB9d5Bw/TgP8rDUvC9gid7onNPbHRLTvB2f1/ofvd2gt1ej3s7n0gO8sEdNp5LbXg/QENpQ="
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		t.Fatalf("unable to decode base64 encoded signature: %v", err)
	}
	pub, err := utils.UnmarshalPEMToPub([]byte(rsaPubKey))
	if err != nil {
		t.Fatalf("unable to parse a PEM encoded public key: %v", err)
	}
	if err := verifier.VerifySignature(payload, sigBytes, pub); err != nil {
		t.Errorf("invalid RSA_PKCS1V15_SHA256 signature: %v", err)
	}
}

func TestRSAPKCS1V15VerifySignatureFailedCases(t *testing.T) {
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
			signature: "MNjVDEwKqOTlhSX4q8HW2scapRUfDlqfIa1n7yMg5PlD/sHPrXT1FKf7BDW7ZRYxBS3CMNoEQbonjE8OVU9oEeewi0t1ddfF3FidcB9d5Bw/TgP8rDUvC9gid7onNPbHRLTvB2f1/ofvd2gt1ej3s7n0gO8sEdNp5LbXg/QENpQ=",
			pubKey:    rsaPubKey,
			wantErr:   "verification error",
		},
		{
			name:      "VerifySiganture failed with unsupported hash function",
			hashFunc:  crypto.MD5,
			payload:   []byte("hello world!"),
			signature: "MNjVDEwKqOTlhSX4q8HW2scapRUfDlqfIa1n7yMg5PlD/sHPrXT1FKf7BDW7ZRYxBS3CMNoEQbonjE8OVU9oEeewi0t1ddfF3FidcB9d5Bw/TgP8rDUvC9gid7onNPbHRLTvB2f1/ofvd2gt1ej3s7n0gO8sEdNp5LbXg/QENpQ=",
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
			signature: "MNjVDEwKqOTlhSX4q8HW2scapRUfDlqfIa1n7yMg5PlD/sHPrXT1FKf7BDW7ZRYxBS3CMNoEQbonjE8OVU9oEeewi0t1ddfF3FidcB9d5Bw/TgP8rDUvC9gid7onNPbHRLTvB2f1/ofvd2gt1ej3s7n0gO8sEdNp5LbXg/QENpQ=",
			pubKey:    mismatchedPubKey,
			wantErr:   "verification error",
		},
		{
			name:      "VerifySignature failed with ECDSA public key",
			hashFunc:  crypto.SHA256,
			payload:   []byte("hello world!"),
			signature: "MNjVDEwKqOTlhSX4q8HW2scapRUfDlqfIa1n7yMg5PlD/sHPrXT1FKf7BDW7ZRYxBS3CMNoEQbonjE8OVU9oEeewi0t1ddfF3FidcB9d5Bw/TgP8rDUvC9gid7onNPbHRLTvB2f1/ofvd2gt1ej3s7n0gO8sEdNp5LbXg/QENpQ=",
			pubKey:    ecdsaPubKey,
			wantErr:   "public key is not a rsa public key",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			verifier := &RSAPKCS1V15Verifier{hashFunc: tc.hashFunc}
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
