package verifier

import (
	"crypto"
	"crypto/ecdsa"
	"errors"
	"fmt"
)

type ECDSAVerifier struct {
	hashFunc crypto.Hash
}

var _ Verifier = ECDSAVerifier{}

func (v ECDSAVerifier) VerifySignature(payload, signature []byte, pubKey crypto.PublicKey) error {
	if signature == nil {
		return errors.New("invalid signature: signature is nil")
	}
	pub, ok := pubKey.(*ecdsa.PublicKey)
	if !ok {
		return fmt.Errorf("public key is not an ECDSA public key")
	}
	if !pub.Curve.IsOnCurve(pub.X, pub.Y) {
		return fmt.Errorf("invalid ECDSA public key, the given (x, y) not on curve: %v", pub.Params().Name)
	}
	digest := computeDigest(v.hashFunc, payload)
	if digest == nil {
		return errors.New("failed to compute digest: invalid hash function specified")
	}
	if !ecdsa.VerifyASN1(pub, digest, signature) {
		return errors.New("invalid ECDSA signature")
	}
	return nil
}
