package key_protection_service

import (
	"fmt"
	"testing"

	kpskcc "github.com/google/go-tpm-tools/keymanager/key_protection_service/key_custody_core"
	"github.com/google/uuid"
)

func TestServiceGenerateKEMKeypairSuccess(t *testing.T) {
	expectedUUID := uuid.New()
	expectedPubKey := make([]byte, 32)
	for i := range expectedPubKey {
		expectedPubKey[i] = byte(i + 10)
	}

	svc := NewService(
		func(bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
			if len(bindingPubKey) != 32 {
				t.Fatalf("expected 32-byte binding public key, got %d", len(bindingPubKey))
			}
			if lifespanSecs != 7200 {
				t.Fatalf("expected lifespanSecs 7200, got %d", lifespanSecs)
			}
			return expectedUUID, expectedPubKey, nil
		},
		func() ([]kpskcc.KEMKeyInfo, error) {
			return nil, nil
		},
	)

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
	svc := NewService(
		func(bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
			return uuid.Nil, nil, fmt.Errorf("FFI error")
		},
		func() ([]kpskcc.KEMKeyInfo, error) {
			return nil, nil
		},
	)

	_, _, err := svc.GenerateKEMKeypair(make([]byte, 32), 3600)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestServiceEnumerateKEMKeysSuccess(t *testing.T) {
	expectedKeys := []kpskcc.KEMKeyInfo{
		{
			ID:                    uuid.New(),
			KemAlgorithm:          1,
			KdfAlgorithm:          1,
			AeadAlgorithm:         1,
			KEMPubKey:             make([]byte, 32),
			BindingPubKey:         make([]byte, 32),
			RemainingLifespanSecs: 3500,
		},
	}

	svc := NewService(
		func(bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
			return uuid.Nil, nil, nil
		},
		func() ([]kpskcc.KEMKeyInfo, error) {
			return expectedKeys, nil
		},
	)

	keys, err := svc.EnumerateKEMKeys()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].ID != expectedKeys[0].ID {
		t.Fatalf("expected ID %s, got %s", expectedKeys[0].ID, keys[0].ID)
	}
}

func TestServiceEnumerateKEMKeysError(t *testing.T) {
	svc := NewService(
		func(bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
			return uuid.Nil, nil, nil
		},
		func() ([]kpskcc.KEMKeyInfo, error) {
			return nil, fmt.Errorf("enumerate error")
		},
	)

	_, err := svc.EnumerateKEMKeys()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
