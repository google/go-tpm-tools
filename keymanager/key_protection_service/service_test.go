package keyprotectionservice

import (
	"fmt"
	"testing"

	"github.com/google/uuid"

	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
)

type mockKPS struct {
	generateKEMKeypairFn func(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error)
	decapAndSealFn       func(kemUUID uuid.UUID, encapsulatedKey, aad []byte) ([]byte, []byte, error)
}

func (m *mockKPS) GenerateKEMKeypair(algo *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	if m.generateKEMKeypairFn != nil {
		return m.generateKEMKeypairFn(algo, bindingPubKey, lifespanSecs)
	}
	return uuid.Nil, nil, nil
}

func (m *mockKPS) DecapAndSeal(kemUUID uuid.UUID, encapsulatedKey, aad []byte) ([]byte, []byte, error) {
	if m.decapAndSealFn != nil {
		return m.decapAndSealFn(kemUUID, encapsulatedKey, aad)
	}
	return nil, nil, nil
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
