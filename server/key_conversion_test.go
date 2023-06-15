package server

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	"github.com/google/go-tpm/legacy/tpm2"
)

func getECCTemplate(curve tpm2.EllipticCurve) tpm2.Public {
	public := client.DefaultEKTemplateECC()
	public.ECCParameters.CurveID = curve
	public.ECCParameters.Point.XRaw = nil
	public.ECCParameters.Point.YRaw = nil
	return public
}

func TestCreateEKPublicAreaFromKeyGeneratedKey(t *testing.T) {
	keys := []struct {
		name        string
		template    tpm2.Public
		generateKey func() (crypto.PublicKey, error)
	}{
		{"RSA", client.DefaultEKTemplateRSA(), func() (crypto.PublicKey, error) {
			priv, err := rsa.GenerateKey(rand.Reader, 2048)
			return priv.Public(), err
		}},
		{"ECC", client.DefaultEKTemplateECC(), func() (crypto.PublicKey, error) {
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			return priv.Public(), err
		}},
		{"ECC-P224", getECCTemplate(tpm2.CurveNISTP224), func() (crypto.PublicKey, error) {
			priv, err := ecdsa.GenerateKey(elliptic.P224(), rand.Reader)
			return priv.Public(), err
		}},
		{"ECC-P256", getECCTemplate(tpm2.CurveNISTP256), func() (crypto.PublicKey, error) {
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			return priv.Public(), err
		}},
		{"ECC-P384", getECCTemplate(tpm2.CurveNISTP384), func() (crypto.PublicKey, error) {
			priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			return priv.Public(), err
		}},
		{"ECC-P521", getECCTemplate(tpm2.CurveNISTP521), func() (crypto.PublicKey, error) {
			priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
			return priv.Public(), err
		}},
	}
	for _, k := range keys {
		t.Run(k.name, func(t *testing.T) {
			key, err := k.generateKey()
			if err != nil {
				t.Fatal(err)
			}
			newArea, err := CreateEKPublicAreaFromKey(key)
			if err != nil {
				t.Fatalf("failed to create public area from public key: %v", err)
			}
			if !newArea.MatchesTemplate(k.template) {
				t.Errorf("public areas did not match. got: %+v want: %+v", newArea, k.template)
			}
		})
	}
}

func TestCreateEKPublicAreaFromKeyTPMKey(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	keys := []struct {
		name     string
		template tpm2.Public
	}{
		{"RSA", client.DefaultEKTemplateRSA()},
		{"ECC", client.DefaultEKTemplateECC()},
		{"ECC-P224", getECCTemplate(tpm2.CurveNISTP224)},
		{"ECC-P256", getECCTemplate(tpm2.CurveNISTP256)},
		{"ECC-P384", getECCTemplate(tpm2.CurveNISTP384)},
		{"ECC-P521", getECCTemplate(tpm2.CurveNISTP521)},
	}
	for _, k := range keys {
		t.Run(k.name, func(t *testing.T) {
			ek, err := client.NewKey(rwc, tpm2.HandleEndorsement, k.template)
			if err != nil {
				t.Fatal(err)
			}
			defer ek.Close()
			newArea, err := CreateEKPublicAreaFromKey(ek.PublicKey())
			if err != nil {
				t.Fatalf("failed to create public area from public key: %v", err)
			}
			if matches, err := ek.Name().MatchesPublic(newArea); err != nil || !matches {
				t.Error("public areas did not match or match check failed.")
			}
		})
	}
}
