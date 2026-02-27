//go:build integration

package kpskcc

import (
	"testing"

	"github.com/google/uuid"

	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
)

var defaultAlgo = &keymanager.HpkeAlgorithm{
	Kem:  keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
	Kdf:  keymanager.KdfAlgorithm_KDF_ALGORITHM_HKDF_SHA256,
	Aead: keymanager.AeadAlgorithm_AEAD_ALGORITHM_AES_256_GCM,
}

func TestIntegrationGenerateKEMKeypair(t *testing.T) {
	// 32-byte X25519 public key (dummy for testing)
	bindingPK := make([]byte, 32)
	for i := range bindingPK {
		bindingPK[i] = byte(i + 1)
	}

	id, pubKey, err := GenerateKEMKeypair(defaultAlgo, bindingPK, 3600)
	if err != nil {
		t.Fatalf("GenerateKEMKeypair failed: %v", err)
	}
	if id == uuid.Nil {
		t.Fatal("expected non-nil UUID")
	}
	if len(pubKey) == 0 {
		t.Fatal("expected non-empty public key")
	}
	t.Logf("Generated KEM key handle: %s, pubkey len: %d", id, len(pubKey))
}

func TestIntegrationGenerateKEMKeypairEmptyPK(t *testing.T) {
	_, _, err := GenerateKEMKeypair(defaultAlgo, []byte{}, 3600)
	if err == nil {
		t.Fatal("expected error for empty binding public key")
	}
}

func TestIntegrationGenerateKEMKeypairUniqueness(t *testing.T) {
	bindingPK := make([]byte, 32)
	for i := range bindingPK {
		bindingPK[i] = byte(i + 1)
	}

	id1, _, err := GenerateKEMKeypair(defaultAlgo, bindingPK, 3600)
	if err != nil {
		t.Fatalf("first GenerateKEMKeypair failed: %v", err)
	}
	id2, _, err := GenerateKEMKeypair(defaultAlgo, bindingPK, 3600)
	if err != nil {
		t.Fatalf("second GenerateKEMKeypair failed: %v", err)
	}
	if id1 == id2 {
		t.Fatalf("expected unique UUIDs, got same: %s", id1)
	}
}

func TestIntegrationGetKemKey(t *testing.T) {
	bindingPK := make([]byte, 32)
	for i := range bindingPK {
		bindingPK[i] = byte(i + 50)
	}

	id, pubKey, err := GenerateKEMKeypair(defaultAlgo, bindingPK, 3600)
	if err != nil {
		t.Fatalf("GenerateKEMKeypair failed: %v", err)
	}

	retrievedKemPK, retrievedBindingPK, deleteAfter, err := GetKemKey(id)
	if err != nil {
		t.Fatalf("GetKemKey failed: %v", err)
	}

	if len(retrievedKemPK) != len(pubKey) {
		t.Fatalf("expected KEM pubkey length %d, got %d", len(pubKey), len(retrievedKemPK))
	}
	for i := range pubKey {
		if pubKey[i] != retrievedKemPK[i] {
			t.Fatalf("KEM pubkey mismatch at index %d", i)
		}
	}

	if len(retrievedBindingPK) != len(bindingPK) {
		t.Fatalf("expected binding pubkey length %d, got %d", len(bindingPK), len(retrievedBindingPK))
	}
	for i := range bindingPK {
		if bindingPK[i] != retrievedBindingPK[i] {
			t.Fatalf("binding pubkey mismatch at index %d", i)
		}
	}

	if deleteAfter == 0 {
		t.Fatal("expected non-zero deleteAfter timestamp")
	}
}

func TestIntegrationGetKemKeyNotFound(t *testing.T) {
	_, _, _, err := GetKemKey(uuid.New())
	if err == nil {
		t.Fatal("expected error for non-existent UUID")
	}
}
