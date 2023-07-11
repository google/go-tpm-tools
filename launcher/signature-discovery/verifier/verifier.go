package verifier

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"github.com/google/go-tpm-tools/launcher/signature-discovery/oci"
	"github.com/google/go-tpm-tools/launcher/signature-discovery/oci/cosign"
)

const (
	PKIXPublicKey  = "PUBLIC KEY"
	PKCS1PublicKey = "RSA PUBLIC KEY"
)

type Verifier interface {
	VerifySignature(payload, signature []byte, pubKey crypto.PublicKey) error
}

func VerifyOCISignature(sig oci.Signature) error {
	if err := oci.ValidSig(sig); err != nil {
		return err
	}

	payload, _ := sig.Payload()
	signature, _ := sig.Base64Encoded()
	sigBytes, err := base64.StdEncoding.DecodeString(signature)
	if err != nil {
		return err
	}

	pub, _ := sig.PubBase64Encoded()
	pubBytes, _ := base64.StdEncoding.DecodeString(pub)
	if err != nil {
		return err
	}
	pubKey, err := unmarshalPEMToPublicKey(pubBytes)
	if err != nil {
		return err
	}

	sigAlg, _ := sig.SigningAlgorithm()
	verifier, err := loadVerifier(sigAlg)
	if err != nil {
		return err
	}
	return verifier.VerifySignature(payload, sigBytes, pubKey)
}

func loadVerifier(signingAlgorithm string) (Verifier, error) {
	switch signingAlgorithm {
	case cosign.RsassaPssSha256:
		return &RSAPSSVerifier{hashFunc: crypto.SHA256}, nil
	case cosign.RsassaPkcs1v5Sha256:
		return &RSAPKCS1V15Verifier{hashFunc: crypto.SHA256}, nil
	case cosign.EcdsaP256Sha256:
		return &ECDSAVerifier{hashFunc: crypto.SHA256}, nil
	default:
		return nil, fmt.Errorf("unable to load signature verifier due to unsupported signing algorithm: %s", signingAlgorithm)
	}
}

func unmarshalPEMToPublicKey(pemBytes []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	switch block.Type {
	case PKIXPublicKey:
		return x509.ParsePKIXPublicKey(block.Bytes)
	case PKCS1PublicKey:
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("failed to unmarshal PEM formatted public key to a crypto.PublicKey: %v", block.Type)
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
