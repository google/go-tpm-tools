package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/google/go-tpm/tpm2"
)

// VerifyOpts enables optional Verify functionality based on
// how the caller wants to verify the AK pub.
type VerifyOpts interface {
}

type TrustedKeyOpt struct {
	trustedKey crypto.PublicKey
}

func (t TrustedKeyOpt) Equals(akPubArea []byte) error {
	tpm2Public, err := tpm2.DecodePublic(akPubArea)
	if err != nil {
		return fmt.Errorf("failed to decode attestation's AK pub: %v", err)
	}
	akKey, err := tpm2Public.Key()
	if err != nil {
		return fmt.Errorf("failed to retrieve public key from AK pub Area: %v", err)
	}
	switch val := akKey.(type) {
	case *rsa.PublicKey:
	case *ecdsa.PublicKey:
		if !val.Equal(t.trustedKey) {
			return errors.New("failed to match attestation's AK pub with trusted key")
		}
	default:
		return fmt.Errorf("key type %T not supported", val)
	}
	return nil
}
