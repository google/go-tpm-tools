//go:build integration

package workload_service

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	kpskcc "github.com/google/go-tpm-tools/keymanager/key_protection_service/key_custody_core"
	wskcc "github.com/google/go-tpm-tools/keymanager/workload_service/key_custody_core"
	"github.com/google/uuid"
)

// RealBindingKeyGen wraps the WSD KCC FFI.
type RealBindingKeyGen struct{}

func (g *RealBindingKeyGen) GenerateBindingKeypair() (uuid.UUID, []byte, error) {
	return wskcc.GenerateBindingKeypair()
}

// RealKEMKeyGen wraps the KPS KCC FFI.
type RealKEMKeyGen struct{}

func (g *RealKEMKeyGen) GenerateKEMKeypair(bindingPubKey []byte) (uuid.UUID, []byte, error) {
	return kpskcc.GenerateKEMKeypair(bindingPubKey)
}

func TestIntegrationGenerateKeys(t *testing.T) {
	// Initialize real FFI generators.
	bindingGen := &RealBindingKeyGen{}
	kemGen := &RealKEMKeyGen{}

	srv := NewServer(bindingGen, kemGen)

	// Create a request to generate keys.
	req := httptest.NewRequest(http.MethodPost, "/keys:generate", nil)
	w := httptest.NewRecorder()

	// Execute the request.
	srv.Handler().ServeHTTP(w, req)

	// Verify HTTP status.
	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	// Verify response body.
	var resp GenerateKeysResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	kemHandle, err := uuid.Parse(resp.KEMKeyHandle)
	if err != nil {
		t.Fatalf("invalid KEM key handle UUID: %v", err)
	}

	// Verify the registry has the mapping.
	bindingUUID, ok := srv.LookupBindingUUID(kemHandle)
	if !ok {
		t.Fatal("expected KEM UUID to be in registry")
	}
	if bindingUUID == uuid.Nil {
		t.Fatal("expected non-nil binding UUID")
	}

	t.Logf("Successfully generated KEM Key %s linked to Binding Key %s via FFI", kemHandle, bindingUUID)
}
