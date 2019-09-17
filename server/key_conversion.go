package server

import (
	"crypto"
	"crypto/rsa"
	"fmt"

	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
)

// CreateEKPublicAreaFromKey creates a public area from a go interface PublicKey.
// Currently only supports RSA keys.
func CreateEKPublicAreaFromKey(k crypto.PublicKey) (tpm2.Public, error) {
	rsaKey, ok := k.(*rsa.PublicKey)
	if !ok {
		return tpm2.Public{}, fmt.Errorf("unsupported public key type: %v", k)
	}
	public := tpm2tools.DefaultEKTemplateRSA()
	if rsaKey.N.BitLen() != int(public.RSAParameters.KeyBits) {
		return tpm2.Public{}, fmt.Errorf("unexpected RSA modulus size: %d bits", rsaKey.N.BitLen())
	}
	if rsaKey.E != int(public.RSAParameters.Exponent()) {
		return tpm2.Public{}, fmt.Errorf("unexpected RSA exponent: %d", rsaKey.E)
	}
	public.RSAParameters.ModulusRaw = rsaKey.N.Bytes()
	return public, nil
}
