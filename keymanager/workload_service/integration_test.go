//go:build integration

package workload_service

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	kpskcc "github.com/google/go-tpm-tools/keymanager/key_protection_service/key_custody_core"
	wskcc "github.com/google/go-tpm-tools/keymanager/workload_service/key_custody_core"
)

// realBindingKeyGen wraps the actual WSD KCC FFI.
type realBindingKeyGen struct{}

func (r *realBindingKeyGen) GenerateBindingKeypair() (uuid.UUID, error) {
	return wskcc.GenerateBindingKeypair()
}

// realKEMKeyGen wraps the actual KPS KCC FFI.
type realKEMKeyGen struct{}

func (r *realKEMKeyGen) GenerateKEMKeypair(bindingPubKey []byte) (uuid.UUID, error) {
	return kpskcc.GenerateKEMKeypair(bindingPubKey)
}

func TestIntegrationGenerateBindingKeypairEndToEnd(t *testing.T) {
	srv := NewServer(&realBindingKeyGen{}, &realKEMKeyGen{})

	req := httptest.NewRequest(http.MethodPost, "/keys:generateBindingKeypair", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp GenerateBindingKeypairResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	id, err := uuid.Parse(resp.BindingKeyHandle)
	if err != nil {
		t.Fatalf("invalid UUID in response: %v", err)
	}
	if id == uuid.Nil {
		t.Fatal("expected non-nil UUID")
	}
	t.Logf("E2E binding key handle: %s", id)
}

func TestIntegrationGenerateKEMKeypairEndToEnd(t *testing.T) {
	srv := NewServer(&realBindingKeyGen{}, &realKEMKeyGen{})

	// Use a 32-byte dummy binding public key (X25519).
	bindingPK := make([]byte, 32)
	for i := range bindingPK {
		bindingPK[i] = byte(i + 1)
	}

	body, _ := json.Marshal(GenerateKEMKeypairRequest{
		BindingPublicKey: base64.StdEncoding.EncodeToString(bindingPK),
	})
	req := httptest.NewRequest(http.MethodPost, "/keys:generateKEMKeypair", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp GenerateKEMKeypairResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	id, err := uuid.Parse(resp.KEMKeyHandle)
	if err != nil {
		t.Fatalf("invalid UUID in response: %v", err)
	}
	if id == uuid.Nil {
		t.Fatal("expected non-nil UUID")
	}
	t.Logf("E2E KEM key handle: %s", id)
}
