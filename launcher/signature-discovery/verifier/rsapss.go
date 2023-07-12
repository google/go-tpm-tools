package verifier

import (
	"crypto"
	"crypto/rsa"
	"errors"
)

// RSAPSSVerifier implements Verifier interface and uses RSA PSS signing algorithm.
type RSAPSSVerifier struct {
	hashFunc crypto.Hash
	pssOpts  *rsa.PSSOptions
}

// Verify that our RSAPSSVerifier struct implements the expected public interface.
var _ Verifier = RSAPSSVerifier{}

// VerifySignature verifies the siganture for the given payload and public key using RSA PSS signing algorithm.
// This method will use rsa.PSSSaltLengthAuto by default if no pssOpts specified.
// This method will return nil if the verification succeeded, otherwise return an error.
func (v RSAPSSVerifier) VerifySignature(payload, signature []byte, pubKey crypto.PublicKey) error {
	if signature == nil {
		return errors.New("invalid signature: signature is nil")
	}
	pub, ok := pubKey.(*rsa.PublicKey)
	if !ok {
		return errors.New("public key is not a rsa public key")
	}

	// set pssOpts.SaltLength if not defined.
	if v.pssOpts == nil {
		v.pssOpts = &rsa.PSSOptions{
			SaltLength: rsa.PSSSaltLengthAuto,
		}
	}

	digest := computeDigest(v.hashFunc, payload)
	if digest == nil {
		return errors.New("failed to compute digest: invalid hash function specified")
	}
	return rsa.VerifyPSS(pub, v.hashFunc, digest, signature, v.pssOpts)
}
