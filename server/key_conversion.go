package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"

	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
)

// CreateEKPublicAreaFromKey creates a public area from a go interface PublicKey.
// Supports RSA and ECC keys.
func CreateEKPublicAreaFromKey(k crypto.PublicKey) (tpm2.Public, error) {
	switch key := k.(type) {
	case *rsa.PublicKey:
		return createEKPublicRSA(key)
	case *ecdsa.PublicKey:
		return createEKPublicECC(key)
	default:
		return tpm2.Public{}, fmt.Errorf("unsupported public key type: %T", k)
	}
}

func createEKPublicRSA(rsaKey *rsa.PublicKey) (tpm2.Public, error) {
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

func createEKPublicECC(eccKey *ecdsa.PublicKey) (public tpm2.Public, err error) {
	public = tpm2tools.DefaultEKTemplateECC()
	public.ECCParameters.CurveID, err = goCurveToCurveID(eccKey)
	if err != nil {
		return tpm2.Public{}, err
	}

	public.ECCParameters.Point = tpm2.ECPoint{
		XRaw: eccIntToBytes(eccKey.X, eccKey),
		YRaw: eccIntToBytes(eccKey.Y, eccKey),
	}
	return public, nil
}
