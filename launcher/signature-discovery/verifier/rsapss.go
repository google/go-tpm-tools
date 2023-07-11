package verifier

import (
	"crypto"
	"crypto/rsa"
	"fmt"
)

type RSAPSSVerifier struct {
	hashFunc crypto.Hash
}

var _ Verifier = RSAPSSVerifier{}

func (v RSAPSSVerifier) VerifySignature(payload, signature []byte, pubKey crypto.PublicKey) error {
	pub, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not a rsa public key")
	}

	digest := computeDigest(v.hashFunc, payload)
	return rsa.VerifyPSS(pub, v.hashFunc, digest, signature, &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
	})
}
