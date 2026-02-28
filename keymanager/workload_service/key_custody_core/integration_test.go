//go:build integration

package wskcc

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
