package tpm2tools

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"
	"sync"

	"github.com/google/go-tpm/tpm2"
)

// Global mutex to protect against concurrent TPM access.
var signerMutex sync.Mutex

type tpmSigner struct {
	Key  *Key
	Hash crypto.Hash
}

// Public returns the tpmSigners public key.
func (signer *tpmSigner) Public() crypto.PublicKey {
	return signer.Key.PublicKey()
}

// Sign uses the TPM key to sign the digest.
// The digest must be hashed from the same hash algorithm as the keys scheme.
// The opts hash function must also match the keys scheme.
// Concurrent use of Sign is thread safe, but it is not safe to access the TPM
// from other sources while Sign is executing.
func (signer *tpmSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	if _, ok := opts.(*rsa.PSSOptions); ok {
		return nil, fmt.Errorf("signing with PSS not supported")
	}
	if opts.HashFunc() != signer.Hash {
		return nil, fmt.Errorf("opts hash: %v does not match the keys signing hash: %v", opts.HashFunc(), signer.Hash)
	}
	if len(digest) != signer.Hash.Size() {
		return nil, fmt.Errorf("digest length: %d does not match hash size: %d", digest, signer.Hash.Size())
	}

	signerMutex.Lock()
	defer signerMutex.Unlock()

	sig, err := tpm2.Sign(signer.Key.rw, signer.Key.handle, "", digest, nil)
	if err != nil {
		return nil, err
	}
	return sig.RSA.Signature, nil
}

// GetSigner returns a crypto.Signer wrapping the loaded TPM Key.
// Concurrent use of one or more Signers is thread safe, but it is not safe to
// access the TPM from other sources while using a Signer.
// The returned Signer lasts the lifetime of the Key, and will no longer work
// once the Key has been closed.
func (k *Key) GetSigner() (crypto.Signer, error) {
	if k.pubArea.Type != tpm2.AlgRSA {
		return nil, fmt.Errorf("only RSA keys are supported")
	}
	if k.pubArea.AuthPolicy != nil {
		return nil, fmt.Errorf("keys with auth policies are not supported")
	}
	if k.hasAttribute(tpm2.FlagRestricted) {
		return nil, fmt.Errorf("restricted keys are not supported")
	}
	if !k.hasAttribute(tpm2.FlagSign) {
		return nil, fmt.Errorf("non-signing key used with GetSigner()")
	}
	if k.pubArea.RSAParameters.Sign == nil {
		return nil, fmt.Errorf("key missing required signing scheme")
	}
	if k.pubArea.RSAParameters.Sign.Alg != tpm2.AlgRSASSA {
		return nil, fmt.Errorf("only RSASSA signing keys are supported")
	}
	hash, err := k.pubArea.RSAParameters.Sign.Hash.Hash()
	if err != nil {
		return nil, err
	}
	return &tpmSigner{k, hash}, nil
}
