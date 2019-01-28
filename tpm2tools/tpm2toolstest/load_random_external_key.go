package tpm2toolstest

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/google/go-tpm-tools/simulator"
	"github.com/samdamana/go-tpm/tpm2"
)

// LoadRandomExternalKey loads a randomly generated external key into the
// TPM simulator. If any errors occur, calls t.Fatal() on the passed testing.T.
func LoadRandomExternalKey(t *testing.T, simulator *simulator.Simulator) {
	pk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public := tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA1,
		Attributes: tpm2.FlagSign | tpm2.FlagSensitiveDataOrigin | tpm2.FlagUserWithAuth,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA1,
			},
			KeyBits:  2048,
			Exponent: uint32(pk.PublicKey.E),
			Modulus:  pk.PublicKey.N,
		},
	}
	private := tpm2.Private{
		Type:      tpm2.AlgRSA,
		Sensitive: pk.Primes[0].Bytes(),
	}
	_, _, err = tpm2.LoadExternal(simulator, public, private, tpm2.HandleNull)
	if err != nil {
		t.Fatal(err)
	}
}
