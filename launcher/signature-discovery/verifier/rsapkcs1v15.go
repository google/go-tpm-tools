package verifier

import (
	"crypto"
	"crypto/rsa"
	"fmt"
)

type RSAPKCS1V15Verifier struct {
	hashFunc crypto.Hash
}

var _ Verifier = RSAPKCS1V15Verifier{}

func (v RSAPKCS1V15Verifier) VerifySignature(payload, signature []byte, pubKey crypto.PublicKey) error {
	pub, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not a rsa public key")
	}
	digest := computeDigest(v.hashFunc, payload)

	return rsa.VerifyPKCS1v15(pub, v.hashFunc, digest, signature)
}
