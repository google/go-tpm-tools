package verifier

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"fmt"
)

// RSAPKCS1V15Verifier implements Verifier interface and uses RSA PKCS1v1.5 signing algorithm.
type RSAPKCS1V15Verifier struct {
	hashFunc crypto.Hash
}

// Verify that our RSAPKCS1V15Verifier struct implements the expected public interface.
var _ Verifier = RSAPKCS1V15Verifier{}

// VerifySignature verifies the siganture for the given payload and public key using RSA PKCS1v1.5 signing algorithm.
// This method will return nil if the verification succeeded, otherwise return an error.
func (v RSAPKCS1V15Verifier) VerifySignature(payload, signature []byte, pubKey crypto.PublicKey) error {
	if signature == nil {
		return errors.New("invalid signature: signature is nil")
	}
	pub, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not a rsa public key")
	}
	digest := computeDigest(v.hashFunc, payload)
	if digest == nil {
		return errors.New("failed to compute digest: invalid hash function specified")
	}
	return rsa.VerifyPKCS1v15(pub, v.hashFunc, digest, signature)
}
