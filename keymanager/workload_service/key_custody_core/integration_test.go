//go:build integration

package wskcc

import (
	"testing"

	"github.com/google/uuid"
)

func TestIntegrationGenerateBindingKeypair(t *testing.T) {
	id, err := GenerateBindingKeypair()
	if err != nil {
		t.Fatalf("GenerateBindingKeypair failed: %v", err)
	}
	if id == uuid.Nil {
		t.Fatal("expected non-nil UUID")
	}
	t.Logf("Generated binding key handle: %s", id)
}

func TestIntegrationGenerateBindingKeypairUniqueness(t *testing.T) {
	id1, err := GenerateBindingKeypair()
	if err != nil {
		t.Fatalf("first GenerateBindingKeypair failed: %v", err)
	}
	id2, err := GenerateBindingKeypair()
	if err != nil {
		t.Fatalf("second GenerateBindingKeypair failed: %v", err)
	}
	if id1 == id2 {
		t.Fatalf("expected unique UUIDs, got same: %s", id1)
	}
}
