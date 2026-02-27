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
	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
	wskcc "github.com/google/go-tpm-tools/keymanager/workload_service/key_custody_core"
)

// realWorkloadService wraps the actual WSD KCC FFI.
type realWorkloadService struct{}

func (r *realWorkloadService) GenerateBindingKeypair(algo *keymanager.HpkeAlgorithm, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return wskcc.GenerateBindingKeypair(algo, lifespanSecs)
}

// realOpener wraps the actual WSD KCC FFI for Open.
type realOpener struct{}

func (r *realOpener) Open(bindingUUID uuid.UUID, enc, ciphertext, aad []byte) ([]byte, error) {
	return wskcc.Open(bindingUUID, enc, ciphertext, aad)
}

func TestIntegrationGenerateKeysEndToEnd(t *testing.T) {
	// Wire up real FFI calls: WSD KCC for binding, KPS KCC (via KPS KOL) for KEM.
	kpsSvc := kps.NewService(kpskcc.GenerateKEMKeypair, kpskcc.DecapAndSeal)
	srv, _ := NewServer(kpsSvc, &realWorkloadService{}, "test.sock")

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
	kpsSvc := kps.NewService(kpskcc.GenerateKEMKeypair, kpskcc.DecapAndSeal)
	srv, _ := NewServer(kpsSvc, &realWorkloadService{}, "test.sock")

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
