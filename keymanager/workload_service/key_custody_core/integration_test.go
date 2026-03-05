//go:build integration

package wskcc

import (
	"bytes"
	"testing"

	"github.com/google/uuid"

	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
)

var defaultAlgo = &keymanager.HpkeAlgorithm{
	Kem:  keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
	Kdf:  keymanager.KdfAlgorithm_KDF_ALGORITHM_HKDF_SHA256,
	Aead: keymanager.AeadAlgorithm_AEAD_ALGORITHM_AES_256_GCM,
}

func TestIntegrationGenerateBindingKeypair(t *testing.T) {
	id, pubKey, err := GenerateBindingKeypair(defaultAlgo, 3600)
	if err != nil {
		t.Fatalf("GenerateBindingKeypair failed: %v", err)
	}
	if id == uuid.Nil {
		t.Fatal("expected non-nil UUID")
	}
	if len(pubKey) == 0 {
		t.Fatal("expected non-empty public key")
	}
	t.Logf("Generated binding key handle: %s, pubkey len: %d", id, len(pubKey))
}

func TestIntegrationGenerateBindingKeypairUniqueness(t *testing.T) {
	id1, pubKey1, err := GenerateBindingKeypair(defaultAlgo, 3600)
	if err != nil {
		t.Fatalf("first GenerateBindingKeypair failed: %v", err)
	}
	id2, pubKey2, err := GenerateBindingKeypair(defaultAlgo, 3600)
	if err != nil {
		t.Fatalf("second GenerateBindingKeypair failed: %v", err)
	}
	if id1 == id2 {
		t.Fatalf("expected unique UUIDs, got same: %s", id1)
	}
	if len(pubKey1) == 0 || len(pubKey2) == 0 {
		t.Fatal("expected non-empty public keys")
	}
}

func TestIntegrationGetBindingKey(t *testing.T) {
	id, pubKey, err := GenerateBindingKeypair(defaultAlgo, 3600)
	if err != nil {
		t.Fatalf("GenerateBindingKeypair failed: %v", err)
	}

	retrievedPubKey, retrievedAlgo, err := GetBindingKey(id)
	if err != nil {
		t.Fatalf("GetBindingKey failed: %v", err)
	}

	if len(retrievedPubKey) != len(pubKey) {
		t.Fatalf("expected pubkey length %d, got %d", len(pubKey), len(retrievedPubKey))
	}

	if !bytes.Equal(pubKey, retrievedPubKey) {
		t.Fatalf("retrieved public key does not match generated public key.\nExpected: %x\nGot:      %x", pubKey, retrievedPubKey)
	}

	if retrievedAlgo.Kem != defaultAlgo.Kem || retrievedAlgo.Kdf != defaultAlgo.Kdf || retrievedAlgo.Aead != defaultAlgo.Aead {
		t.Fatalf("algorithm mismatch: expected %v, got %v", defaultAlgo, retrievedAlgo)
	}
}

func TestIntegrationGetBindingKeyNotFound(t *testing.T) {
	_, _, err := GetBindingKey(uuid.New())
	if err == nil {
		t.Fatal("expected error for non-existent UUID")
	}
}
