package client_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	// Maximum number of handles to keys tests can create within a simulator.
	maxHandles = 3
)

func TestHandles(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	expected := make([]tpmutil.Handle, 0)
	for i := 0; i < maxHandles; i++ {
		expected = append(expected, test.LoadRandomExternalKey(t, rwc))

		handles, err := client.Handles(rwc, tpm2.HandleTypeTransient)
		if err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(handles, expected) {
			t.Errorf("Handles mismatch got: %v; want: %v", handles, expected)
		}
	}

	// Don't leak our handles
	for _, handle := range expected {
		if err := tpm2.FlushContext(rwc, handle); err != nil {
			t.Error(err)
		}
	}
}

func TestFindHandle(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	// Persist three keys: two ECC and one RSA. Finding each key proves the
	// public keys were actually compared: with two ECC keys in the TPM,
	// matching on the algorithm alone is not enough.
	akECC, err := client.AttestationKeyECC(rwc)
	if err != nil {
		t.Fatal(err)
	}
	defer akECC.Close()

	akRSA, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		t.Fatal(err)
	}
	defer akRSA.Close()

	// This key sits at a higher handle than the ECC AK, and handles are
	// searched in ascending order, so finding this key means FindHandle
	// walked past a same-algorithm key and rejected it.
	signingECC, err := client.NewCachedKey(rwc, tpm2.HandleOwner, templateECC(tpm2.AlgSHA256), tpmutil.Handle(0x81008F02))
	if err != nil {
		t.Fatal(err)
	}
	defer signingECC.Close()

	keys := []struct {
		name string
		key  *client.Key
	}{
		{"AK-ECC", akECC},
		{"AK-RSA", akRSA},
		{"Signing-ECC", signingECC},
	}
	for _, k := range keys {
		t.Run(k.name, func(t *testing.T) {
			handle, err := client.FindHandle(rwc, k.key.PublicKey())
			if err != nil {
				t.Fatal(err)
			}
			if handle != k.key.Handle() {
				t.Errorf("expected handle %v, got: %v", k.key.Handle(), handle)
			}
		})
	}
}

func TestFindHandleFoundKeySigns(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	// Create a signing key in the TPM, keeping only its public key. This
	// mirrors a real client, who knows the public key from a certificate
	// but does not know the handle.
	provisioned, err := client.NewCachedKey(rwc, tpm2.HandleOwner, templateECC(tpm2.AlgSHA256), tpmutil.Handle(0x81008F02))
	if err != nil {
		t.Fatal(err)
	}
	pub := provisioned.PublicKey()
	provisioned.Close()

	handle, err := client.FindHandle(rwc, pub)
	if err != nil {
		t.Fatal(err)
	}
	key, err := client.LoadCachedKey(rwc, handle, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer key.Close()

	signer, err := key.GetSigner()
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("proof of possession"))
	sig, err := signer.Sign(nil, digest[:], crypto.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	if !verifyECC(pub, crypto.SHA256, digest[:], sig) {
		t.Error("signature from recovered key does not verify against the public key that found it")
	}
}

func TestFindHandleIgnoresTransientKeys(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	// LoadRandomExternalKey loads its key with TPM2_LoadExternal, and every
	// loaded object is transient. The check below guards against the helper
	// changing.
	handle := test.LoadRandomExternalKey(t, rwc)
	defer func() {
		if err := tpm2.FlushContext(rwc, handle); err != nil {
			t.Error(err)
		}
	}()
	if byte(handle>>24) != byte(tpm2.HandleTypeTransient) {
		t.Fatalf("expected a transient handle, got: %#x", handle)
	}

	pubArea, _, _, err := tpm2.ReadPublic(rwc, handle)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := pubArea.Key()
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.FindHandle(rwc, pub); !errors.Is(err, client.ErrNoKeyFound) {
		t.Errorf("expected ErrNoKeyFound, got: %v", err)
	}
}

// keyWithoutEqual mimics a public key type with no Equal method, such as the
// *dsa.PublicKey an x509.Certificate carrying a DSA key yields.
type keyWithoutEqual struct{}

func TestFindHandleUncomparableKey(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	_, err := client.FindHandle(rwc, keyWithoutEqual{})
	if err == nil || errors.Is(err, client.ErrNoKeyFound) {
		t.Errorf("expected a comparison error, got: %v", err)
	}
}

func TestFindHandleNoKeyFound(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	// A key the TPM has never seen.
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := client.FindHandle(rwc, priv.Public()); !errors.Is(err, client.ErrNoKeyFound) {
		t.Errorf("expected ErrNoKeyFound, got: %v", err)
	}
}
