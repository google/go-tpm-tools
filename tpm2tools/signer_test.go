package tpm2tools

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"testing"

	"github.com/google/go-tpm-tools/internal"
	"github.com/google/go-tpm/tpm2"
)

func templateSSA(hash tpm2.Algorithm) tpm2.Public {
	template := AIKTemplateRSA(nil)
	// Can't sign arbitrary data if restricted.
	template.Attributes &= ^tpm2.FlagRestricted
	template.RSAParameters.Sign.Hash = hash
	return template
}

func TestSign(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer CheckedClose(t, rwc)

	tests := []struct {
		name     string
		hash     crypto.Hash
		template tpm2.Public
	}{
		{"RSA-SHA1", crypto.SHA1, templateSSA(tpm2.AlgSHA1)},
		{"RSA-SHA256", crypto.SHA256, templateSSA(tpm2.AlgSHA256)},
		{"RSA-SHA384", crypto.SHA384, templateSSA(tpm2.AlgSHA384)},
		{"RSA-SHA512", crypto.SHA512, templateSSA(tpm2.AlgSHA512)},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			key, err := NewKey(rwc, tpm2.HandleEndorsement, test.template)
			if err != nil {
				t.Fatal(err)
			}
			defer key.Close()

			hash := test.hash.New()
			hash.Write([]byte("authenticated message"))
			digest := hash.Sum(nil)

			signer, err := key.GetSigner()
			if err != nil {
				t.Fatal(err)
			}

			sig, err := signer.Sign(nil, digest, test.hash)
			if err != nil {
				t.Fatal(err)
			}
			pubKey := signer.Public().(*rsa.PublicKey)
			if err := rsa.VerifyPKCS1v15(pubKey, test.hash, digest, sig); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestSignIncorrectHash(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer CheckedClose(t, rwc)

	key, err := NewKey(rwc, tpm2.HandleEndorsement, templateSSA(tpm2.AlgSHA256))
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()

	signer, err := key.GetSigner()
	if err != nil {
		t.Fatal(err)
	}

	digestSHA1 := sha1.Sum([]byte("authenticated message"))
	digestSHA256 := sha256.Sum256([]byte("authenticated message"))

	if _, err := signer.Sign(nil, digestSHA1[:], crypto.SHA1); err == nil {
		t.Error("expected failure for digest and hash not matching keys sigScheme.")
	}

	if _, err := signer.Sign(nil, digestSHA1[:], crypto.SHA256); err == nil {
		t.Error("expected failure for correct hash, but incorrect digest.")
	}

	if _, err := signer.Sign(nil, digestSHA256[:], crypto.SHA1); err == nil {
		t.Error("expected failure for correct digest, but incorrect hash.")
	}
}
