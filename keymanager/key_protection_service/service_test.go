package key_protection_service

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
)

// noopDecapAndSeal is a placeholder for tests that don't exercise DecapAndSeal.
func noopDecapAndSeal(_ uuid.UUID, _, _ []byte) ([]byte, []byte, error) {
	return nil, nil, nil
}

func TestServiceGenerateKEMKeypairSuccess(t *testing.T) {
	expectedUUID := uuid.New()
	expectedPubKey := make([]byte, 32)
	for i := range expectedPubKey {
		expectedPubKey[i] = byte(i + 10)
	}

	svc := NewService(func(bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
		if len(bindingPubKey) != 32 {
			t.Fatalf("expected 32-byte binding public key, got %d", len(bindingPubKey))
		}
		if lifespanSecs != 7200 {
			t.Fatalf("expected lifespanSecs 7200, got %d", lifespanSecs)
		}
		return expectedUUID, expectedPubKey, nil
	}, noopDecapAndSeal)

	id, pubKey, err := svc.GenerateKEMKeypair(make([]byte, 32), 7200)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != expectedUUID {
		t.Fatalf("expected UUID %s, got %s", expectedUUID, id)
	}
	if len(pubKey) != 32 {
		t.Fatalf("expected 32-byte public key, got %d", len(pubKey))
	}
}

func TestServiceGenerateKEMKeypairError(t *testing.T) {
	svc := NewService(func(bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
		return uuid.Nil, nil, fmt.Errorf("FFI error")
	}, noopDecapAndSeal)

	_, _, err := svc.GenerateKEMKeypair(make([]byte, 32), 3600)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestServiceDecapAndSealSuccess(t *testing.T) {
	kemUUID := uuid.New()
	expectedSealEnc := []byte("seal-enc-key")
	expectedSealedCT := []byte("sealed-ciphertext")

	svc := NewService(nil, func(id uuid.UUID, encKey, aad []byte) ([]byte, []byte, error) {
		if id != kemUUID {
			t.Fatalf("expected KEM UUID %s, got %s", kemUUID, id)
		}
		return expectedSealEnc, expectedSealedCT, nil
	})

	sealEnc, sealedCT, err := svc.DecapAndSeal(kemUUID, []byte("enc-key"), []byte("aad"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(sealEnc) != string(expectedSealEnc) {
		t.Fatalf("expected seal enc %q, got %q", expectedSealEnc, sealEnc)
	}
	if string(sealedCT) != string(expectedSealedCT) {
		t.Fatalf("expected sealed CT %q, got %q", expectedSealedCT, sealedCT)
	}
}

func TestServiceDecapAndSealError(t *testing.T) {
	svc := NewService(nil, func(_ uuid.UUID, _, _ []byte) ([]byte, []byte, error) {
		return nil, nil, fmt.Errorf("decap FFI error")
	})

	_, _, err := svc.DecapAndSeal(uuid.New(), []byte("enc-key"), nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
