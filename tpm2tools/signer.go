package tpm2tools

import (
	"crypto"
	"crypto/rsa"
<<<<<<< HEAD
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"sync"

	"github.com/google/go-tpm/tpm2"
)

// Global mutex to protect against concurrent TPM access.
var signerMutex sync.Mutex

type tpmSigner struct {
	Key  *Key
	Hash crypto.Hash
=======
	"fmt"
	"io"
	"sync"

	"github.com/google/go-tpm/tpm2"
)

var (
	// Global mutex to protect against concurrent TPM read/writes.
	signerMutex = &sync.Mutex{}
)

// TpmSigner implements the crypto.Signer interface for TPM Keys.
// Concurrent use of one or more TpmSigners is thread safe, but it is not safe
// to read/write to the TPM from other sources while using a TpmSigner.
type TpmSigner struct {
	key *Key
>>>>>>> 81cb72b... Format and change comments
}

// Public returns the tpmSigners public key.
func (signer *tpmSigner) Public() crypto.PublicKey {
	return signer.Key.PublicKey()
}

<<<<<<< HEAD
// Sign uses the TPM key to sign the digest.
// The digest must be hashed from the same hash algorithm as the keys scheme.
// The opts hash function must also match the keys scheme.
// Concurrent use of Sign is thread safe, but it is not safe to access the TPM
// from other sources while Sign is executing.
func (signer *tpmSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
=======
// Sign uses the TPM key to  sign the digest.
// The digest must be hashed from the same hash algorithm as the keys scheme.
// The opts hash function must also match the keys scheme.
// Concurrent use of Sign is thread safe, but it is not safe to read/write to
// the TPM from other sources while Sign is executing.
func (signer TpmSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
>>>>>>> 81cb72b... Format and change comments
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

<<<<<<< HEAD
	switch sig.Alg {
	case tpm2.AlgRSASSA:
		return sig.RSA.Signature, nil
	case tpm2.AlgECDSA:
		sigStruct := struct{ R, S *big.Int }{sig.ECC.R, sig.ECC.S}
		return asn1.Marshal(sigStruct)
	default:
		panic("unsupported signing algorithm")
	}
}
=======
	public := signer.key.pubArea

	switch public.Type {
	case tpm2.AlgRSA:
		if hash != public.RSAParameters.Sign.Hash {
			return nil, fmt.Errorf("opts hash: %v does not match the keys signing hash: %v", hash, public.RSAParameters.Sign.Hash)
		}
>>>>>>> 81cb72b... Format and change comments

// GetSigner returns a crypto.Signer wrapping the loaded TPM Key.
// Concurrent use of one or more Signers is thread safe, but it is not safe to
// access the TPM from other sources while using a Signer.
// The returned Signer lasts the lifetime of the Key, and will no longer work
// once the Key has been closed.
func (k *Key) GetSigner() (crypto.Signer, error) {
	if k.pubArea.AuthPolicy != nil {
		return nil, fmt.Errorf("keys with auth policies are not supported")
	}
	if k.hasAttribute(tpm2.FlagRestricted) {
		return nil, fmt.Errorf("restricted keys are not supported")
	}
	if !k.hasAttribute(tpm2.FlagSign) {
		return nil, fmt.Errorf("non-signing key used with GetSigner()")
	}

<<<<<<< HEAD
	var sigScheme *tpm2.SigScheme
	var sigAlg tpm2.Algorithm
=======
		sig, err := tpm2.Sign(signer.key.rw, signer.key.handle, "", digest, nil)
		if err != nil {
			return nil, err
		}
		return sig.RSA.Signature, nil
	default:
		return nil, fmt.Errorf("unsupported key type: %v", public.Type)
	}
}
>>>>>>> 81cb72b... Format and change comments

	switch k.pubArea.Type {
	case tpm2.AlgRSA:
		sigScheme = k.pubArea.RSAParameters.Sign
		sigAlg = tpm2.AlgRSASSA
	case tpm2.AlgECC:
		sigScheme = k.pubArea.ECCParameters.Sign
		sigAlg = tpm2.AlgECDSA
	default:
		return nil, fmt.Errorf("unsupported key type: %v", k.pubArea.Type)
	}
	if sigScheme == nil {
		return nil, fmt.Errorf("key missing required signing scheme")
	}
	if sigScheme.Alg != sigAlg {
		return nil, fmt.Errorf("unsupported signing algorithm: %v", sigScheme.Alg)
	}
	hash, err := sigScheme.Hash.Hash()
	if err != nil {
		return nil, err
	}
	return &tpmSigner{k, hash}, nil
}
