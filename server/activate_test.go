package server

import (
	"bytes"
	"io"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal"
)

func TestActivateCredentialEndorsementHierarchyRSAAK(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	ak, err := client.AttestationKeyRSAPrimary(rwc)
	if err != nil {
		t.Fatal(err)
	}
	defer ak.Close()

	testActivateCredential(t, rwc, ak)
}

func TestActivateCredentialStorageHierarchyRSAAK(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	// first create SRK RSA
	srk, err := client.StorageRootKeyRSA(rwc)
	if err != nil {
		t.Fatal(err)
	}
	defer srk.Close()

	ak, err := client.AttestationKeyRSAChild(rwc)
	if err != nil {
		t.Fatal(err)
	}
	defer ak.Close()

	testActivateCredential(t, rwc, ak)
}

func testActivateCredential(t *testing.T, rw io.ReadWriter, ak *client.Key) {
	ek, err := client.EndorsementKeyRSA(rw)
	defer ek.Close()
	if err != nil {
		t.Fatal(err)
	}

	secret, credBlob, encSecret, err := GenerateChallenge(nil, ek.PublicKey(), ak.PublicArea())
	if err != nil {
		t.Fatalf("GenerateChallenge failed: %v", err)
	}

	decryptedSecret, err := ak.ActivateCredential(rw, ek, credBlob, encSecret)
	if err != nil {
		t.Fatalf("ActivateCredential failed: %v", err)
	}
	if !bytes.Equal(secret, decryptedSecret) {
		t.Error("secret does not match decrypted secret")
		t.Logf("Secret = %v", secret)
		t.Logf("Decrypted secret = %v", decryptedSecret)
	}
}
