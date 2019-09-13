package server

import (
	"crypto/rand"
	"github.com/google/go-tpm-tools/tpm2tools"
	"io"
	"testing"
)

func TestCreateEKPublicAreaFromKey(t *testing.T) {
	area := tpm2tools.DefaultEKTemplateRSA()
	if _, err := io.ReadFull(rand.Reader, area.RSAParameters.ModulusRaw); err != nil {
		t.Fatal(err)
	}
	key, err := area.Key()
	if err != nil {
		t.Fatal(err)
	}
	newArea, err := CreateEKPublicAreaFromKey(key)
	if err != nil {
		t.Fatalf("failed to create public area from public key: %v", err)
	}
	if !newArea.MatchesTemplate(area) {
		t.Errorf("public areas did not match. got: %+v want: %v", newArea, area)
	}
}
