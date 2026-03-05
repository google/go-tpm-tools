package keyprotectionservice

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	kpskcc "github.com/google/go-tpm-tools/keymanager/key_protection_service/key_custody_core"
	"github.com/google/uuid"

	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
)

type mockKPS struct {
	generateKEMKeypairFn func(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error)
	decapAndSealFn       func(kemUUID uuid.UUID, encapsulatedKey, aad []byte) ([]byte, []byte, error)
	enumerateKEMKeysFn   func(limit, offset int) ([]kpskcc.KEMKeyInfo, bool, error)
	destroyKEMKeyFn      func(kemUUID uuid.UUID) error
	GetKEMKeyFn          func(id uuid.UUID) ([]byte, []byte, *keymanager.HpkeAlgorithm, uint64, error)
}

func (m *mockKPS) GenerateKEMKeypair(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	if m.generateKEMKeypairFn != nil {
		return m.generateKEMKeypairFn(algo, bindingPubKey, lifespanSecs)
	}
	return uuid.Nil, nil, nil
}

func (m *mockKPS) EnumerateKEMKeys(limit, offset int) ([]kpskcc.KEMKeyInfo, bool, error) {
	if m.enumerateKEMKeysFn != nil {
		return m.enumerateKEMKeysFn(limit, offset)
	}
	return nil, false, nil
}

func (m *mockKPS) DecapAndSeal(kemUUID uuid.UUID, encapsulatedKey, aad []byte) ([]byte, []byte, error) {
	if m.decapAndSealFn != nil {
		return m.decapAndSealFn(kemUUID, encapsulatedKey, aad)
	}
	return nil, nil, nil
}

func (m *mockKPS) GetKEMKey(id uuid.UUID) ([]byte, []byte, *keymanager.HpkeAlgorithm, uint64, error) {
	return m.GetKEMKeyFn(id)
}

func (m *mockKPS) DestroyKEMKey(kemUUID uuid.UUID) error {
	if m.destroyKEMKeyFn != nil {
		return m.destroyKEMKeyFn(kemUUID)
	}
	return nil
}

func TestServiceGenerateKEMKeypairSuccess(t *testing.T) {
	expectedUUID := uuid.New()
	expectedPubKey := make([]byte, 32)
	for i := range expectedPubKey {
		expectedPubKey[i] = byte(i + 10)
	}

	mock := &mockKPS{
		generateKEMKeypairFn: func(_ *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
			if len(bindingPubKey) != 32 {
				t.Fatalf("expected 32-byte binding public key, got %d", len(bindingPubKey))
			}
			if lifespanSecs != 7200 {
				t.Fatalf("expected lifespanSecs 7200, got %d", lifespanSecs)
			}
			return expectedUUID, expectedPubKey, nil
		},
	}

	svc := newServiceWithKPS(mock)

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
	mock := &mockKPS{
		generateKEMKeypairFn: func(_ *keymanager.HpkeAlgorithm, _ []byte, _ uint64) (uuid.UUID, []byte, error) {
			return uuid.Nil, nil, fmt.Errorf("FFI error")
		},
	}

	svc := newServiceWithKPS(mock)

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

	mock := &mockKPS{
		enumerateKEMKeysFn: func(limit, offset int) ([]kpskcc.KEMKeyInfo, bool, error) {
			if limit != 100 || offset != 0 {
				return nil, false, fmt.Errorf("unexpected limit/offset: %d/%d", limit, offset)
			}
			return expectedKeys, false, nil
		},
	}
	svc := newServiceWithKPS(mock)

	keys, _, err := svc.EnumerateKEMKeys(100, 0)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].ID != expectedKeys[0].ID {
		t.Errorf("expected ID %s, got %s", expectedKeys[0].ID, keys[0].ID)
	}
	if !reflect.DeepEqual(keys[0].Algorithm, expectedKeys[0].Algorithm) {
		t.Errorf("expected Algorithm %v, got %v", expectedKeys[0].Algorithm, keys[0].Algorithm)
	}
	if !bytes.Equal(keys[0].KEMPubKey, expectedKeys[0].KEMPubKey) {
		t.Errorf("expected KEMPubKey %x, got %x", expectedKeys[0].KEMPubKey, keys[0].KEMPubKey)
	}
	// Note: We explicitly ignore RemainingLifespanSecs as it may vary slightly
	// based on the time of checking.
}

func TestServiceEnumerateKEMKeysError(t *testing.T) {
	mock := &mockKPS{
		enumerateKEMKeysFn: func(_, _ int) ([]kpskcc.KEMKeyInfo, bool, error) {
			return nil, false, fmt.Errorf("enumerate error")
		},
	}
	svc := newServiceWithKPS(mock)

	_, _, err := svc.EnumerateKEMKeys(100, 0)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestServiceDestroyKEMKeySuccess(t *testing.T) {
	kemUUID := uuid.New()
	mock := &mockKPS{
		destroyKEMKeyFn: func(id uuid.UUID) error {
			if id != kemUUID {
				t.Fatalf("expected KEM UUID %s, got %s", kemUUID, id)
			}
			return nil
		},
	}

	svc := newServiceWithKPS(mock)

	if err := svc.DestroyKEMKey(kemUUID); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestServiceDestroyKEMKeyError(t *testing.T) {
	mock := &mockKPS{
		destroyKEMKeyFn: func(_ uuid.UUID) error {
			return fmt.Errorf("destroy FFI error")
		},
	}

	svc := newServiceWithKPS(mock)

	err := svc.DestroyKEMKey(uuid.New())
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestServiceDecapAndSealSuccess(t *testing.T) {
	kemUUID := uuid.New()
	expectedSealEnc := []byte("seal-enc-key")
	expectedSealedCT := []byte("sealed-ciphertext")

	mock := &mockKPS{
		decapAndSealFn: func(id uuid.UUID, _, _ []byte) ([]byte, []byte, error) {
			if id != kemUUID {
				t.Fatalf("expected KEM UUID %s, got %s", kemUUID, id)
			}
			return expectedSealEnc, expectedSealedCT, nil
		},
	}

	svc := newServiceWithKPS(mock)

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
	mock := &mockKPS{
		decapAndSealFn: func(_ uuid.UUID, _, _ []byte) ([]byte, []byte, error) {
			return nil, nil, fmt.Errorf("decap FFI error")
		},
	}

	svc := newServiceWithKPS(mock)

	_, _, err := svc.DecapAndSeal(uuid.New(), []byte("enc-key"), nil)
	if err == nil {
		t.Fatal("expected error, got nil")
	}
}

func TestServiceGetKEMKeySuccess(t *testing.T) {
	expectedKemPubKey := make([]byte, 32)
	for i := range expectedKemPubKey {
		expectedKemPubKey[i] = byte(i + 1)
	}
	expectedBindingPubKey := make([]byte, 32)
	for i := range expectedBindingPubKey {
		expectedBindingPubKey[i] = byte(i + 10)
	}
	expectedAlgo := &keymanager.HpkeAlgorithm{
		Kem:  keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
		Kdf:  keymanager.KdfAlgorithm_KDF_ALGORITHM_HKDF_SHA256,
		Aead: keymanager.AeadAlgorithm_AEAD_ALGORITHM_AES_256_GCM,
	}
	expectedRemainingLifespanSecs := uint64(3600)
	keyID := uuid.New()

	mock := &mockKPS{
		GetKEMKeyFn: func(id uuid.UUID) ([]byte, []byte, *keymanager.HpkeAlgorithm, uint64, error) {
			if id != keyID {
				t.Fatalf("expected UUID %s, got %s", keyID, id)
			}
			return expectedKemPubKey, expectedBindingPubKey, expectedAlgo, expectedRemainingLifespanSecs, nil
		},
	}

	svc := newServiceWithKPS(mock)

	kemPubKey, bindingPubKey, algo, remainingLifespanSecs, err := svc.GetKEMKey(keyID)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !bytes.Equal(kemPubKey, expectedKemPubKey) {
		t.Fatalf("expected KEM public key %x, got %x", expectedKemPubKey, kemPubKey)
	}
	if !bytes.Equal(bindingPubKey, expectedBindingPubKey) {
		t.Fatalf("expected binding public key %x, got %x", expectedBindingPubKey, bindingPubKey)
	}
	if algo.Kem != expectedAlgo.Kem || algo.Kdf != expectedAlgo.Kdf || algo.Aead != expectedAlgo.Aead {
		t.Fatalf("expected algorithm %v, got %v", expectedAlgo, algo)
	}
	if remainingLifespanSecs != expectedRemainingLifespanSecs {
		t.Fatalf("expected remainingLifespanSecs %d, got %d", expectedRemainingLifespanSecs, remainingLifespanSecs)
	}
}
