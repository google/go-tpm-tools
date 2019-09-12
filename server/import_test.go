package server

import (
	"bytes"
	"github.com/google/go-tpm-tools/internal"
	"github.com/google/go-tpm-tools/tpm2tools"
	"testing"
)

func TestImport(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer tpm2tools.CheckedClose(t, rwc)

	ek, err := tpm2tools.EndorsementKeyRSA(rwc)
	if err != nil {
		t.Fatal(err)
	}
	pub := ek.PublicKey()
	secret := []byte("super secret code")
	blob, err := CreateImportBlob(pub, secret)
	if err != nil {
		t.Fatalf("creating import blob failed: %v", err)
	}

	output, err := ek.Import(rwc, blob)
	if err != nil {
		t.Fatalf("import failed: %v", err)
	}

	if !bytes.Equal(output, secret) {
		t.Errorf("got %X, expected %X", output, secret)
	}
}
