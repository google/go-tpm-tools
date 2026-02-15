//go:build integration

package kpskcc

import (
	"testing"

	"github.com/google/uuid"
)

func TestIntegrationGenerateKEMKeypair(t *testing.T) {
	// 32-byte X25519 public key (dummy for testing)
	bindingPK := make([]byte, 32)
	for i := range bindingPK {
		bindingPK[i] = byte(i + 1)
	}

	id, pubKey, err := GenerateKEMKeypair(bindingPK, 3600)
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
	_, _, err := GenerateKEMKeypair([]byte{}, 3600)
	if err == nil {
		t.Fatal("expected error for empty binding public key")
	}
}

func TestIntegrationGenerateKEMKeypairUniqueness(t *testing.T) {
	bindingPK := make([]byte, 32)
	for i := range bindingPK {
		bindingPK[i] = byte(i + 1)
	}

	id1, _, err := GenerateKEMKeypair(bindingPK, 3600)
	if err != nil {
		t.Fatalf("first GenerateKEMKeypair failed: %v", err)
	}
	id2, _, err := GenerateKEMKeypair(bindingPK, 3600)
	if err != nil {
		t.Fatalf("second GenerateKEMKeypair failed: %v", err)
	}
	if id1 == id2 {
		t.Fatalf("expected unique UUIDs, got same: %s", id1)
	}
}
