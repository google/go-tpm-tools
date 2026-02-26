//go:build integration

package workloadservice

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"

	kps "github.com/google/go-tpm-tools/keymanager/key_protection_service"
	kpskcc "github.com/google/go-tpm-tools/keymanager/key_protection_service/key_custody_core"
	algorithms "github.com/google/go-tpm-tools/keymanager/km_common/proto"
	wskcc "github.com/google/go-tpm-tools/keymanager/workload_service/key_custody_core"
)

// realWorkloadService wraps the actual WSD KCC FFI.
type realWorkloadService struct{}

func (r *realWorkloadService) GenerateBindingKeypair(algo *algorithms.HpkeAlgorithm, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return wskcc.GenerateBindingKeypair(algo, lifespanSecs)
}

func (r *realWorkloadService) DestroyBindingKey(bindingUUID uuid.UUID) error {
	return wskcc.DestroyBindingKey(bindingUUID)
}

func TestIntegrationGenerateKeysEndToEnd(t *testing.T) {
	// Wire up real FFI calls: WSD KCC for binding, KPS KCC (via KPS KOL) for KEM.
	kpsSvc := kps.NewService(kpskcc.GenerateKEMKeypair, kpskcc.DestroyKEMKey)
	srv, err := NewServer(kpsSvc, &realWorkloadService{}, "")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	reqBody, err := json.Marshal(GenerateKemRequest{
		Algorithm:              KemAlgorithmDHKEMX25519HKDFSHA256,
		KeyProtectionMechanism: KeyProtectionMechanismVM,
		Lifespan:               ProtoDuration{Seconds: 3600},
	})
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_kem", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp GenerateKemResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	kemUUID, err := uuid.Parse(resp.KeyHandle.Handle)
	if err != nil {
		t.Fatalf("invalid UUID in response: %v", err)
	}
	if kemUUID == uuid.Nil {
		t.Fatal("expected non-nil KEM UUID")
	}

	// Verify the KEM → Binding mapping was stored.
	bindingUUID, ok := srv.LookupBindingUUID(kemUUID)
	if !ok {
		t.Fatal("expected KEM UUID to have a mapping to binding UUID")
	}
	if bindingUUID == uuid.Nil {
		t.Fatal("expected non-nil binding UUID in map")
	}

	t.Logf("E2E: KEM key handle=%s, mapped binding handle=%s", kemUUID, bindingUUID)
}

func TestIntegrationGenerateKeysUniqueMappings(t *testing.T) {
	kpsSvc := kps.NewService(kpskcc.GenerateKEMKeypair, kpskcc.DestroyKEMKey)
	srv, err := NewServer(kpsSvc, &realWorkloadService{}, "")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// Generate two key sets.
	var kemUUIDs [2]uuid.UUID
	for i := 0; i < 2; i++ {
		reqBody, err := json.Marshal(GenerateKemRequest{
			Algorithm:              KemAlgorithmDHKEMX25519HKDFSHA256,
			KeyProtectionMechanism: KeyProtectionMechanismVM,
			Lifespan:               ProtoDuration{Seconds: 3600},
		})
		if err != nil {
			t.Fatalf("call %d: failed to marshal request: %v", i+1, err)
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_kem", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("call %d: expected status 200, got %d: %s", i+1, w.Code, w.Body.String())
		}

		var resp GenerateKemResponse
		if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
			t.Fatalf("call %d: failed to decode response: %v", i+1, err)
		}

		id, err := uuid.Parse(resp.KeyHandle.Handle)
		if err != nil {
			t.Fatalf("call %d: invalid UUID: %v", i+1, err)
		}
		kemUUIDs[i] = id
	}

	if kemUUIDs[0] == kemUUIDs[1] {
		t.Fatalf("expected unique KEM UUIDs, got same: %s", kemUUIDs[0])
	}

	// Verify mappings are unique.
	binding1, _ := srv.LookupBindingUUID(kemUUIDs[0])
	binding2, _ := srv.LookupBindingUUID(kemUUIDs[1])
	if binding1 == binding2 {
		t.Fatalf("expected unique binding UUIDs, got same: %s", binding1)
	}

	t.Logf("E2E uniqueness: KEM1=%s→Binding1=%s, KEM2=%s→Binding2=%s",
		kemUUIDs[0], binding1, kemUUIDs[1], binding2)
}

func TestIntegrationDestroyKey(t *testing.T) {
	kpsSvc := kps.NewService(kpskcc.GenerateKEMKeypair, kpskcc.DestroyKEMKey)
	srv, err := NewServer(kpsSvc, &realWorkloadService{}, "")
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}

	// 1. Generate a key first
	reqBody, _ := json.Marshal(GenerateKemRequest{
		Algorithm:              KemAlgorithmDHKEMX25519HKDFSHA256,
		KeyProtectionMechanism: KeyProtectionMechanismVM,
		Lifespan:               ProtoDuration{Seconds: 3600},
	})
	reqGen := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_kem", bytes.NewReader(reqBody))
	reqGen.Header.Set("Content-Type", "application/json")
	wGen := httptest.NewRecorder()
	srv.Handler().ServeHTTP(wGen, reqGen)

	if wGen.Code != http.StatusOK {
		t.Fatalf("setup: expected generate status 200, got %d: %s", wGen.Code, wGen.Body.String())
	}

	var respGen GenerateKemResponse
	if err := json.NewDecoder(wGen.Body).Decode(&respGen); err != nil {
		t.Fatalf("setup: failed to decode generate response: %v", err)
	}
	kemHandle := respGen.KeyHandle.Handle
	kemUUID, err := uuid.Parse(kemHandle)
	if err != nil {
		t.Fatalf("setup: invalid KEM UUID: %v", err)
	}

	// Verify mapping exists
	_, ok := srv.LookupBindingUUID(kemUUID)
	if !ok {
		t.Fatal("setup: expected mapping to exist")
	}

	// 2. Destroy the key
	reqDestroyBody, _ := json.Marshal(DestroyRequest{
		KeyHandle: KeyHandle{Handle: kemHandle},
	})
	reqDestroy := httptest.NewRequest(http.MethodPost, "/v1/keys:destroy", bytes.NewReader(reqDestroyBody))
	reqDestroy.Header.Set("Content-Type", "application/json")
	wDestroy := httptest.NewRecorder()
	srv.Handler().ServeHTTP(wDestroy, reqDestroy)

	if wDestroy.Code != http.StatusNoContent {
		t.Fatalf("expected destroy status 204, got %d: %s", wDestroy.Code, wDestroy.Body.String())
	}

	// 3. Verify mapping is gone
	_, ok = srv.LookupBindingUUID(kemUUID)
	if ok {
		t.Fatal("expected KEM UUID mapping to be removed after destroy")
	}

	// 4. Try to destroy again (should fail? or be 404? or 500?)
	// If mapping is gone, it returns 404.
	reqDestroy2 := httptest.NewRequest(http.MethodPost, "/v1/keys:destroy", bytes.NewReader(reqDestroyBody))
	reqDestroy2.Header.Set("Content-Type", "application/json")
	wDestroy2 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(wDestroy2, reqDestroy2)

	if wDestroy2.Code != http.StatusNotFound {
		t.Fatalf("expected second destroy to return 404, got %d", wDestroy2.Code)
	}
}
