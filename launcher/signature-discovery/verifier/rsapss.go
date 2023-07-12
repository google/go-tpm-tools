package verifier

import (
	"crypto"
	"crypto/rsa"
	"errors"
)

type RSAPSSVerifier struct {
	hashFunc crypto.Hash
	pssOpts  *rsa.PSSOptions
}

var _ Verifier = RSAPSSVerifier{}

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
