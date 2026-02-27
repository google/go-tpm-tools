package keyprotectionservice

import (
	"fmt"
	"testing"

	"github.com/google/uuid"

	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
)

type mockKeyProtectionService struct {
	generateKEMKeypairFn func(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error)
	getKemKeyFn          func(id uuid.UUID) ([]byte, []byte, uint64, error)
}

func (m *mockKeyProtectionService) GenerateKEMKeypair(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return m.generateKEMKeypairFn(algo, bindingPubKey, lifespanSecs)
}

func (m *mockKeyProtectionService) GetKemKey(id uuid.UUID) ([]byte, []byte, uint64, error) {
	return m.getKemKeyFn(id)
}

func TestServiceGenerateKEMKeypairSuccess(t *testing.T) {
	expectedUUID := uuid.New()
	expectedPubKey := make([]byte, 32)
	for i := range expectedPubKey {
		expectedPubKey[i] = byte(i + 10)
	}

	svc := NewService(&mockKeyProtectionService{
		generateKEMKeypairFn: func(_ *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
			if len(bindingPubKey) != 32 {
				t.Fatalf("expected 32-byte binding public key, got %d", len(bindingPubKey))
			}
			if lifespanSecs != 7200 {
				t.Fatalf("expected lifespanSecs 7200, got %d", lifespanSecs)
			}
			return expectedUUID, expectedPubKey, nil
		},
	})

	id, pubKey, err := svc.GenerateKEMKeypair(&keymanager.HpkeAlgorithm{}, make([]byte, 32), 7200)
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
	svc := NewService(&mockKeyProtectionService{
		generateKEMKeypairFn: func(_ *keymanager.HpkeAlgorithm, _ []byte, _ uint64) (uuid.UUID, []byte, error) {
			return uuid.Nil, nil, fmt.Errorf("FFI error")
		},
	})

	_, _, err := svc.GenerateKEMKeypair(&keymanager.HpkeAlgorithm{}, make([]byte, 32), 3600)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestServiceGetKemKeySuccess(t *testing.T) {
	expectedKemPubKey := make([]byte, 32)
	expectedBindingPubKey := make([]byte, 32)
	expectedDeleteAfter := uint64(12345678)
	keyID := uuid.New()

	svc := NewService(&mockKeyProtectionService{
		getKemKeyFn: func(id uuid.UUID) ([]byte, []byte, uint64, error) {
			if id != keyID {
				t.Fatalf("expected UUID %s, got %s", keyID, id)
			}
			return expectedKemPubKey, expectedBindingPubKey, expectedDeleteAfter, nil
		},
	})

	kemPubKey, bindingPubKey, deleteAfter, err := svc.GetKemKey(keyID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(kemPubKey) != 32 {
		t.Fatalf("expected 32-byte KEM public key, got %d", len(kemPubKey))
	}
	if len(bindingPubKey) != 32 {
		t.Fatalf("expected 32-byte binding public key, got %d", len(bindingPubKey))
	}
	if deleteAfter != expectedDeleteAfter {
		t.Fatalf("expected deleteAfter %d, got %d", expectedDeleteAfter, deleteAfter)
	}
}
