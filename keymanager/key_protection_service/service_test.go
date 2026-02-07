package key_protection_service

import (
	"fmt"
	"testing"

	"github.com/google/uuid"
)

func TestServiceGenerateKEMKeypairSuccess(t *testing.T) {
	expectedUUID := uuid.New()
	svc := NewService(func(bindingPubKey []byte) (uuid.UUID, error) {
		if len(bindingPubKey) != 32 {
			t.Fatalf("expected 32-byte binding public key, got %d", len(bindingPubKey))
		}
		return expectedUUID, nil
	})

	id, err := svc.GenerateKEMKeypair(make([]byte, 32))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if id != expectedUUID {
		t.Fatalf("expected UUID %s, got %s", expectedUUID, id)
	}
}

func TestServiceGenerateKEMKeypairError(t *testing.T) {
	svc := NewService(func(bindingPubKey []byte) (uuid.UUID, error) {
		return uuid.Nil, fmt.Errorf("FFI error")
	})

	_, err := svc.GenerateKEMKeypair(make([]byte, 32))
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
