package keyprotectionservice

import (
	"fmt"
	"testing"

	kpskcc "github.com/google/go-tpm-tools/keymanager/key_protection_service/key_custody_core"
	"github.com/google/uuid"

	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
)

func TestServiceGenerateKEMKeypairSuccess(t *testing.T) {
	expectedUUID := uuid.New()
	expectedPubKey := make([]byte, 32)
	for i := range expectedPubKey {
		expectedPubKey[i] = byte(i + 10)
	}

	svc := NewService(
		func(_ *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
			if len(bindingPubKey) != 32 {
				t.Fatalf("expected 32-byte binding public key, got %d", len(bindingPubKey))
			}
			if lifespanSecs != 7200 {
				t.Fatalf("expected lifespanSecs 7200, got %d", lifespanSecs)
			}
			return expectedUUID, expectedPubKey, nil
		},
		func(_, _ int) ([]kpskcc.KEMKeyInfo, bool, error) {
			return nil, false, nil
		},
	)

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
	svc := NewService(
		func(_ *keymanager.HpkeAlgorithm, _ []byte, _ uint64) (uuid.UUID, []byte, error) {
			return uuid.Nil, nil, fmt.Errorf("FFI error")
		},
		func(_, _ int) ([]kpskcc.KEMKeyInfo, bool, error) {
			return nil, false, nil
		},
	)

	_, _, err := svc.GenerateKEMKeypair(&keymanager.HpkeAlgorithm{}, make([]byte, 32), 3600)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestServiceEnumerateKEMKeysSuccess(t *testing.T) {
	expectedKeys := []kpskcc.KEMKeyInfo{
		{
			ID: uuid.New(),
			Algorithm: &keymanager.HpkeAlgorithm{
				Kem:  keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
				Kdf:  keymanager.KdfAlgorithm_KDF_ALGORITHM_HKDF_SHA256,
				Aead: keymanager.AeadAlgorithm_AEAD_ALGORITHM_AES_256_GCM,
			},
			KEMPubKey:             make([]byte, 32),
			RemainingLifespanSecs: 3500,
		},
	}

	svc := NewService(
		func(_ *keymanager.HpkeAlgorithm, _ []byte, _ uint64) (uuid.UUID, []byte, error) {
			return uuid.Nil, nil, nil
		},
		func(limit, offset int) ([]kpskcc.KEMKeyInfo, bool, error) {
			if limit != 100 || offset != 0 {
				return nil, false, fmt.Errorf("unexpected limit/offset: %d/%d", limit, offset)
			}
			return expectedKeys, false, nil
		},
	)

	keys, _, err := svc.EnumerateKEMKeys(100, 0)
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
		func(_ *keymanager.HpkeAlgorithm, _ []byte, _ uint64) (uuid.UUID, []byte, error) {
			return uuid.Nil, nil, nil
		},
		func(_, _ int) ([]kpskcc.KEMKeyInfo, bool, error) {
			return nil, false, fmt.Errorf("enumerate error")
		},
	)

	_, _, err := svc.EnumerateKEMKeys(100, 0)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}
