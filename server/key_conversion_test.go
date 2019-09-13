package server

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/google/go-tpm-tools/internal"
	"github.com/google/go-tpm-tools/tpm2tools"
	"testing"
)

func TestCreateEKPublicAreaFromKeyGeneratedKey(t *testing.T) {
	template := tpm2tools.DefaultEKTemplateRSA()
	key, err := rsa.GenerateKey(rand.Reader, int(template.RSAParameters.KeyBits))
	if err != nil {
		t.Fatal(err)
	}
	newArea, err := CreateEKPublicAreaFromKey(key.Public())
	if err != nil {
		t.Fatalf("failed to create public area from public key: %v", err)
	}
	if !newArea.MatchesTemplate(template) {
		t.Errorf("public areas did not match. got: %+v want: %+v", newArea, template)
	}
}

func TestCreateEKPublicAreaFromKeyTPMKey(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer tpm2tools.CheckedClose(t, rwc)

	ek, err := tpm2tools.EndorsementKeyRSA(rwc)
	if err != nil {
		t.Fatal(err)
	}
	defer ek.Close()
	newArea, err := CreateEKPublicAreaFromKey(ek.PublicKey())

	if matches, err := ek.Name().MatchesPublic(newArea); !matches || err != nil {
		t.Error("public areas did not match.")
	}

}
