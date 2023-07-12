package verifier

import (
	"testing"

	"github.com/google/go-tpm-tools/launcher/signature-discovery/oci"
)

func TestVerifyOCISignature(t *testing.T) {
	sig := &testSig{}
	if err := VerifyOCISignature(sig); err != nil {
		t.Errorf("invalid oci signature: %v", err)
	}
}

func TestLoadverifier(t *testing.T) {
	testCases := []struct {
		name     string
		alg      oci.SigningAlgorithm
		wantPass bool
	}{
		{
			name:     "loadVerifier() success with RSASSA_PSS_SHA256",
			alg:      oci.RsassaPssSha256,
			wantPass: true,
		},
		{
			name:     "loadVerifier() success with RSASSA_PKCS1V15_SHA256",
			alg:      oci.RsassaPkcs1v15Sha256,
			wantPass: true,
		},
		{
			name:     "loadVerifier() success with ECDSA_P256_SHA256",
			alg:      oci.EcdsaP256Sha256,
			wantPass: true,
		},
		{
			name:     "loadVerifier() failed with unsupported signing algorithm",
			alg:      oci.SigningAlgorithm("unsupported signing algorithm"),
			wantPass: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := loadVerifier(tc.alg)
			if got := err == nil; got != tc.wantPass {
				t.Errorf("loadVerifier() failed for test case %s for signing algorithm: %v", tc.name, tc.alg)
			}
		})
	}
}

type testSig struct{}

var _ oci.Signature = testSig{}

func (s testSig) Payload() ([]byte, error) {
	return []byte("hello world!"), nil
}

func (s testSig) Base64Encoded() (string, error) {
	return "MEYCIQDl0nmdnkMBZc5rLmMR3cWOcZbXcBiNyCdhctKN+RpqHAIhALiaSW8gdCiBjxmXNWF8BBKAVu24u9JisY6juSfYbcNF", nil
}

func (s testSig) PublicKey() ([]byte, error) {
	return []byte(ecdsaPubKey), nil
}

func (s testSig) SigningAlgorithm() (oci.SigningAlgorithm, error) {
	return oci.EcdsaP256Sha256, nil
}
