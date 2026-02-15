package key_protection_service

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
)

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
	})

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
	})

	_, _, err := svc.GenerateKEMKeypair(make([]byte, 32), 3600)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
