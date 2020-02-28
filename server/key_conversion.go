package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"io"

	tpmpb "github.com/google/go-tpm-tools/proto"
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
	public.ECCParameters.Point = tpm2.ECPoint{
		XRaw: eccIntToBytes(eccKey.Curve, eccKey.X),
		YRaw: eccIntToBytes(eccKey.Curve, eccKey.Y),
	}
	public.ECCParameters.CurveID, err = goCurveToCurveID(eccKey.Curve)
	return public, err
}

func createPublic(private tpm2.Private, hashAlg tpm2.Algorithm, pcrs *tpmpb.Pcrs) tpm2.Public {
	publicHash := getHash(hashAlg)
	publicHash.Write(private.SeedValue)
	publicHash.Write(private.Sensitive)
	public := tpm2.Public{
		Type:    tpm2.AlgKeyedHash,
		NameAlg: hashAlg,
		KeyedHashParameters: &tpm2.KeyedHashParams{
			Alg:    tpm2.AlgNull,
			Unique: publicHash.Sum(nil),
		},
	}
	if len(pcrs.GetPcrs()) == 0 {
		// Allow password authorization so we can use a nil AuthPolicy.
		public.AuthPolicy = nil
		public.Attributes |= tpm2.FlagUserWithAuth
	} else {
		public.AuthPolicy = tpm2tools.ComputePCRSessionAuth(pcrs)
		public.Attributes |= tpm2.FlagAdminWithPolicy
	}
	return public
}

func createPrivate(sensitive []byte, hashAlg tpm2.Algorithm) tpm2.Private {
	private := tpm2.Private{
		Type:      tpm2.AlgKeyedHash,
		AuthValue: nil,
		SeedValue: make([]byte, getHash(hashAlg).Size()),
		Sensitive: sensitive,
	}
	if _, err := io.ReadFull(rand.Reader, private.SeedValue); err != nil {
		panic(err)
	}
	return private
}
