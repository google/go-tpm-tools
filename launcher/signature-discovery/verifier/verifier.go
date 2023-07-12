package verifier

import (
	"crypto"
	"crypto/sha256"
	"encoding/base64"
	"fmt"

	utils "github.com/google/go-tpm-tools/launcher/signature-discovery"
	"github.com/google/go-tpm-tools/launcher/signature-discovery/oci"
)

type Verifier interface {
	VerifySignature(payload, signature []byte, pubKey crypto.PublicKey) error
}

func VerifyOCISignature(sig oci.Signature) error {
	if err := oci.ValidSig(sig); err != nil {
		return err
	}

	// Decode base64-encoded signature to byte slice.
	signature, _ := sig.Base64Encoded()
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	// Convert a PEM-encoded byte slice to a crypto.PublicKey.
	pub, _ := sig.PublicKey()
	pubKey, err := utils.UnmarshalPEMToPub(pub)
	if err != nil {
		return err
	}

	// Load a signature verifier based on a signing algorithm.
	sigAlg, _ := sig.SigningAlgorithm()
	verifier, err := loadVerifier(sigAlg)
	if err != nil {
		return err
	}
	payload, _ := sig.Payload()
	return verifier.VerifySignature(payload, sigBytes, pubKey)
}

func loadVerifier(sigAlg oci.SigningAlgorithm) (Verifier, error) {
	switch sigAlg {
	case oci.RsassaPssSha256:
		return &RSAPSSVerifier{hashFunc: crypto.SHA256}, nil
	case oci.RsassaPkcs1v15Sha256:
		return &RSAPKCS1V15Verifier{hashFunc: crypto.SHA256}, nil
	case oci.EcdsaP256Sha256:
		return &ECDSAVerifier{hashFunc: crypto.SHA256}, nil
	default:
		return nil, fmt.Errorf("unable to load signature verifier due to unsupported signing algorithm: %s", sigAlg)
	}
}

func computeDigest(hash crypto.Hash, message []byte) []byte {
	switch hash {
	case crypto.SHA256:
		digest := sha256.Sum256(message)
		return digest[:]
	default:
		return nil
	}
}
