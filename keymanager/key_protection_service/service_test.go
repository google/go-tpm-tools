package key_protection_service

import (
	"fmt"
	"testing"

	"github.com/google/uuid"

	algorithms "github.com/google/go-tpm-tools/keymanager/km_common/proto"
)

// noopDestroyKEMKey is a placeholder for tests that don't exercise DestroyKEMKey.
func noopDestroyKEMKey(_ uuid.UUID) error {
	return nil
}
func TestServiceGenerateKEMKeypairSuccess(t *testing.T) {
	expectedUUID := uuid.New()
	expectedPubKey := make([]byte, 32)
	for i := range expectedPubKey {
		expectedPubKey[i] = byte(i + 10)
	}

	svc := NewService(func(algo *algorithms.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
		if len(bindingPubKey) != 32 {
			t.Fatalf("expected 32-byte binding public key, got %d", len(bindingPubKey))
		}
		if lifespanSecs != 7200 {
			t.Fatalf("expected lifespanSecs 7200, got %d", lifespanSecs)
		}
		return expectedUUID, expectedPubKey, nil
	}, noopDestroyKEMKey)

	id, pubKey, err := svc.GenerateKEMKeypair(&algorithms.HpkeAlgorithm{}, make([]byte, 32), 7200)
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
	svc := NewService(func(algo *algorithms.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
		return uuid.Nil, nil, fmt.Errorf("FFI error")
	}, noopDestroyKEMKey)

	_, _, err := svc.GenerateKEMKeypair(&algorithms.HpkeAlgorithm{}, make([]byte, 32), 3600)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestServiceDestroyKEMKeySuccess(t *testing.T) {
	kemUUID := uuid.New()
	svc := NewService(nil, func(id uuid.UUID) error {
		if id != kemUUID {
			t.Fatalf("expected KEM UUID %s, got %s", kemUUID, id)
		}
		return nil
	})

	if err := svc.DestroyKEMKey(kemUUID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServiceDestroyKEMKeyError(t *testing.T) {
	svc := NewService(nil, func(_ uuid.UUID) error {
		return fmt.Errorf("destroy FFI error")
	})

	err := svc.DestroyKEMKey(uuid.New())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
