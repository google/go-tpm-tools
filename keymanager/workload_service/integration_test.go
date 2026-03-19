//go:build integration

package workloadservice

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"

	kps "github.com/google/go-tpm-tools/keymanager/key_protection_service"
	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
	wskcc "github.com/google/go-tpm-tools/keymanager/workload_service/key_custody_core"
)

// realWorkloadService wraps the actual WSD KCC FFI.
type realWorkloadService struct{}

func (r *realWorkloadService) GenerateBindingKeypair(algo *keymanager.HpkeAlgorithm, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return wskcc.GenerateBindingKeypair(algo, lifespanSecs)
}

func (r *realWorkloadService) DestroyBindingKey(bindingUUID uuid.UUID) error {
	return wskcc.DestroyBindingKey(bindingUUID)
}

func (r *realWorkloadService) Open(bindingUUID uuid.UUID, enc, ciphertext, aad []byte) ([]byte, error) {
	return wskcc.Open(bindingUUID, enc, ciphertext, aad)
}

func (r *realWorkloadService) GetBindingKey(id uuid.UUID) ([]byte, *keymanager.HpkeAlgorithm, error) {
	return wskcc.GetBindingKey(id)
}
// setupTestServer initializes a test server with a temporary socket path
// and wires up the workload service with real FFI calls.
func setupTestServer(t *testing.T, socketPath string) *Server {
	t.Helper()
	kpsSvc := kps.NewService()
	srv, err := NewServer(kpsSvc, &realWorkloadService{}, socketPath)
	if err != nil {
		t.Fatalf("failed to create server: %v", err)
	}
	return srv
}

// TestIntegrationGenerateKeysEndToEnd tests the key generation flow end-to-end,
// verifying that keys are generated correctly and their metadata is valid.
func TestIntegrationGenerateKeysEndToEnd(t *testing.T) {
	// Wire up real FFI calls: WSD KCC for binding, KPS KCC (via KPS KOL) for KEM.
	srv := setupTestServer(t, "test.sock")

	reqBody, err := json.Marshal(GenerateKeyRequest{
		Algorithm: AlgorithmDetails{Type: "kem", Params: AlgorithmParams{KemID: KemAlgorithmDHKEMX25519HKDFSHA256}},
		Lifespan:  3600,
	})
	if err != nil {
		t.Fatalf("failed to marshal request: %v", err)
	}
	req := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_key", bytes.NewReader(reqBody))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	validateJSONSchema(t, w.Body.Bytes(), keyInfoSchema)

	var resp GenerateKeyResponse
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
	srv := setupTestServer(t, "test.sock")

	// Generate two key sets.
	var kemUUIDs [2]uuid.UUID
	for i := 0; i < 2; i++ {
		reqBody, err := json.Marshal(GenerateKeyRequest{
			Algorithm: AlgorithmDetails{Type: "kem", Params: AlgorithmParams{KemID: KemAlgorithmDHKEMX25519HKDFSHA256}},
			Lifespan:  3600,
		})
		if err != nil {
			t.Fatalf("call %d: failed to marshal request: %v", i+1, err)
		}
		req := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_key", bytes.NewReader(reqBody))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		srv.Handler().ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Fatalf("call %d: expected status 200, got %d: %s", i+1, w.Code, w.Body.String())
		}

		validateJSONSchema(t, w.Body.Bytes(), keyInfoSchema)

		var resp GenerateKeyResponse
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
	srv := setupTestServer(t, "")

	// 1. Generate a key first
	reqBody, _ := json.Marshal(GenerateKeyRequest{
		Algorithm: AlgorithmDetails{Type: "kem", Params: AlgorithmParams{KemID: KemAlgorithmDHKEMX25519HKDFSHA256}},
		Lifespan:  3600,
	})
	reqGen := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_key", bytes.NewReader(reqBody))
	reqGen.Header.Set("Content-Type", "application/json")
	wGen := httptest.NewRecorder()
	srv.Handler().ServeHTTP(wGen, reqGen)

	if wGen.Code != http.StatusOK {
		t.Fatalf("setup: expected generate status 200, got %d: %s", wGen.Code, wGen.Body.String())
	}

	validateJSONSchema(t, wGen.Body.Bytes(), keyInfoSchema)

	var respGen GenerateKeyResponse
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

func TestIntegrationAutoDestroy(t *testing.T) {
	srv := setupTestServer(t, "test.sock")

	// 1. Generate a key with 1-second lifespan
	reqBody, _ := json.Marshal(GenerateKeyRequest{
		Algorithm: AlgorithmDetails{Type: "kem", Params: AlgorithmParams{KemID: KemAlgorithmDHKEMX25519HKDFSHA256}},
		Lifespan:  1,
	})
	reqGen := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_key", bytes.NewReader(reqBody))
	reqGen.Header.Set("Content-Type", "application/json")
	wGen := httptest.NewRecorder()
	srv.Handler().ServeHTTP(wGen, reqGen)

	if wGen.Code != http.StatusOK {
		t.Fatalf("setup: expected generate status 200, got %d: %s", wGen.Code, wGen.Body.String())
	}

	validateJSONSchema(t, wGen.Body.Bytes(), keyInfoSchema)

	var respGen GenerateKeyResponse
	if err := json.NewDecoder(wGen.Body).Decode(&respGen); err != nil {
		t.Fatalf("failed to decode generate response: %v", err)
	}
	kemHandle := respGen.KeyHandle.Handle

	// Wait for auto-destroy
	time.Sleep(2 * time.Second)

	// 2. Destroy the explicitly auto-destroyed key
	reqDestroyBody, _ := json.Marshal(DestroyRequest{
		KeyHandle: KeyHandle{Handle: kemHandle},
	})
	reqDestroy := httptest.NewRequest(http.MethodPost, "/v1/keys:destroy", bytes.NewReader(reqDestroyBody))
	reqDestroy.Header.Set("Content-Type", "application/json")
	wDestroy := httptest.NewRecorder()
	srv.Handler().ServeHTTP(wDestroy, reqDestroy)

	// In the real system, it gracefully handles destruction and cleans up the KOL mapping.
	if wDestroy.Code != http.StatusNoContent {
		t.Fatalf("expected destroy status 204 or some success, got %d: %s", wDestroy.Code, wDestroy.Body.String())
	}
}

func TestIntegrationKeyClaims(t *testing.T) {
	srv := setupTestServer(t, filepath.Join(t.TempDir(), "test.sock"))
	t.Cleanup(func() {
		srv.listener.Close()
		close(srv.claimsChan)
	})

	// 1. Generate a KEM key
	reqBody, _ := json.Marshal(GenerateKeyRequest{
		Algorithm: AlgorithmDetails{Type: "kem", Params: AlgorithmParams{KemID: KemAlgorithmDHKEMX25519HKDFSHA256}},
		Lifespan:  3600,
	})
	req := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_key", bytes.NewReader(reqBody))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("failed to generate KEM key: %s", w.Body.String())
	}

	var resp GenerateKeyResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode generate response: %v", err)
	}
	kemHandle := resp.KeyHandle.Handle

	// 2. Test GetKeyClaims for KEM key
	t.Run("KemClaimsSuccess", func(t *testing.T) {
		respChan := make(chan *ClaimsResult)
		req := &keymanager.GetKeyClaimsRequest{
			KeyHandle: &keymanager.KeyHandle{Handle: kemHandle},
			KeyType:   keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY,
		}
		srv.claimsChan <- &ClaimsCall{Request: req, RespChan: respChan}

		res := <-respChan
		if res.Err != nil {
			t.Fatalf("unexpected error for KEM claims: %v", res.Err)
		}
		if res.Reply.GetVmKeyClaims() == nil {
			t.Fatal("expected VmKeyClaims")
		}
	})

	// 3. Test GetKeyClaims for Binding key
	t.Run("BindingClaimsSuccess", func(t *testing.T) {

		respChan := make(chan *ClaimsResult)
		req := &keymanager.GetKeyClaimsRequest{
			KeyHandle: &keymanager.KeyHandle{Handle: kemHandle},
			KeyType:   keymanager.KeyType_KEY_TYPE_VM_PROTECTION_BINDING,
		}
		srv.claimsChan <- &ClaimsCall{Request: req, RespChan: respChan}

		res := <-respChan
		if res.Err != nil {
			t.Fatalf("unexpected error for binding claims: %v", res.Err)
		}
		if res.Reply.GetVmBindingClaims() == nil {
			t.Fatal("expected VmBindingClaims")
		}
	})

	// 4. Test non-happy cases
	t.Run("NonExistentKey", func(t *testing.T) {
		respChan := make(chan *ClaimsResult)
		req := &keymanager.GetKeyClaimsRequest{
			KeyHandle: &keymanager.KeyHandle{Handle: uuid.New().String()},
			KeyType:   keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY,
		}
		srv.claimsChan <- &ClaimsCall{Request: req, RespChan: respChan}

		res := <-respChan
		if res.Err == nil {
			t.Fatal("expected error for non-existent key")
		}
	})

	t.Run("UnsupportedKeyType", func(t *testing.T) {
		respChan := make(chan *ClaimsResult)
		req := &keymanager.GetKeyClaimsRequest{
			KeyHandle: &keymanager.KeyHandle{Handle: kemHandle},
			KeyType:   keymanager.KeyType_KEY_TYPE_UNSPECIFIED,
		}
		srv.claimsChan <- &ClaimsCall{Request: req, RespChan: respChan}

		res := <-respChan
		if res.Err == nil {
			t.Fatal("expected error for unsupported key type")
		}
	})
}

// TestIntegrationGetCapabilities tests the /v1/capabilities endpoint,
// verifying that it returns the expected supported algorithms.
func TestIntegrationGetCapabilities(t *testing.T) {
	srv := setupTestServer(t, filepath.Join(t.TempDir(), "test.sock"))
	t.Cleanup(func() {
		srv.listener.Close()
		close(srv.claimsChan)
	})

	req := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	validateJSONSchema(t, w.Body.Bytes(), getCapabilitiesSchema)

	var resp GetCapabilitiesResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(resp.SupportedAlgorithms) == 0 {
		t.Fatal("expected at least one supported algorithm")
	}
}

// TestIntegrationEnumerateKeys tests the /v1/keys endpoint,
// verifying that it lists generated keys and their details correctly.
func TestIntegrationEnumerateKeys(t *testing.T) {
	srv := setupTestServer(t, filepath.Join(t.TempDir(), "test.sock"))
	t.Cleanup(func() {
		srv.listener.Close()
		close(srv.claimsChan)
	})

	// 1. Generate a key to ensure the list is not empty
	reqBody, _ := json.Marshal(GenerateKeyRequest{
		Algorithm: AlgorithmDetails{Type: "kem", Params: AlgorithmParams{KemID: KemAlgorithmDHKEMX25519HKDFSHA256}},
		Lifespan:  3600,
	})
	reqGen := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_key", bytes.NewReader(reqBody))
	wGen := httptest.NewRecorder()
	srv.Handler().ServeHTTP(wGen, reqGen)

	if wGen.Code != http.StatusOK {
		t.Fatalf("setup: failed to generate key: %s", wGen.Body.String())
	}

	var respGen GenerateKeyResponse
	if err := json.NewDecoder(wGen.Body).Decode(&respGen); err != nil {
		t.Fatalf("failed to decode generate response: %v", err)
	}

	// 2. Enumerate keys
	reqEnum := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
	wEnum := httptest.NewRecorder()
	srv.Handler().ServeHTTP(wEnum, reqEnum)

	if wEnum.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", wEnum.Code, wEnum.Body.String())
	}

	validateJSONSchema(t, wEnum.Body.Bytes(), enumerateKeysSchema)

	var respEnum EnumerateKeysResponse
	if err := json.NewDecoder(wEnum.Body).Decode(&respEnum); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	found := false
	for _, ki := range respEnum.KeyInfos {
		if ki.KeyHandle.Handle == respGen.KeyHandle.Handle {
			found = true
			if ki.PubKey.PublicKey != respGen.PubKey.PublicKey {
				t.Errorf("expected PubKey.PublicKey %q, got %q", respGen.PubKey.PublicKey, ki.PubKey.PublicKey)
			}
			if ki.PubKey.Algorithm.Type != respGen.PubKey.Algorithm.Type {
				t.Errorf("expected PubKey.Algorithm.Type %q, got %q", respGen.PubKey.Algorithm.Type, ki.PubKey.Algorithm.Type)
			}
			if ki.PubKey.Algorithm.Params.KemID != respGen.PubKey.Algorithm.Params.KemID {
				t.Errorf("expected PubKey.Algorithm.Params.KemID %q, got %q", respGen.PubKey.Algorithm.Params.KemID, ki.PubKey.Algorithm.Params.KemID)
			}
			if ki.KeyProtectionMechanism != respGen.KeyProtectionMechanism {
				t.Errorf("expected KeyProtectionMechanism %q, got %q", respGen.KeyProtectionMechanism, ki.KeyProtectionMechanism)
			}
			diff := ki.ExpirationTime - respGen.ExpirationTime
			if diff < -2 || diff > 2 {
				t.Errorf("expected ExpirationTime %d (or within 2s), got %d (diff %d)", respGen.ExpirationTime, ki.ExpirationTime, diff)
			}
			break
		}
	}
	if !found {
		t.Fatalf("expected generated key %s to be in the list", respGen.KeyHandle.Handle)
	}
}

// TestIntegrationDecapsulation tests the /v1/keys:decapsulate endpoint,
// verifying that it can correctly decapsulate a shared secret.
func TestIntegrationDecapsulation(t *testing.T) {
	srv := setupTestServer(t, "test.sock")

	// 1. Generate a KEM key
	reqBody, _ := json.Marshal(GenerateKeyRequest{
		Algorithm: AlgorithmDetails{Type: "kem", Params: AlgorithmParams{KemID: KemAlgorithmDHKEMX25519HKDFSHA256}},
		Lifespan:  3600,
	})
	reqGen := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_key", bytes.NewReader(reqBody))
	reqGen.Header.Set("Content-Type", "application/json")
	wGen := httptest.NewRecorder()
	srv.Handler().ServeHTTP(wGen, reqGen)

	if wGen.Code != http.StatusOK {
		t.Fatalf("setup: expected generate status 200, got %d: %s", wGen.Code, wGen.Body.String())
	}

	var respGen GenerateKeyResponse
	if err := json.NewDecoder(wGen.Body).Decode(&respGen); err != nil {
		t.Fatalf("setup: failed to decode generate response: %v", err)
	}
	pkRHex := respGen.PubKey.PublicKey
	pkR, err := base64.StdEncoding.DecodeString(pkRHex)
	if err != nil {
		t.Fatalf("setup: failed to decode recipient public key: %v", err)
	}

	// 2. Encapsulate using helper
	sharedSecret, enc, err := encapsulateDHKEMX25519HKDFSHA256(pkR)
	if err != nil {
		t.Fatalf("failed to encapsulate: %v", err)
	}

	// 3. Call Decapsulate API
	decapReq := DecapsRequest{
		KeyHandle: KeyHandle{Handle: respGen.KeyHandle.Handle},
		Ciphertext: KemCiphertext{
			Algorithm:  KemAlgorithmDHKEMX25519HKDFSHA256,
			Ciphertext: base64.StdEncoding.EncodeToString(enc),
		},
	}
	decapBody, _ := json.Marshal(decapReq)
	reqDecap := httptest.NewRequest(http.MethodPost, "/v1/keys:decap", bytes.NewReader(decapBody))
	reqDecap.Header.Set("Content-Type", "application/json")
	wDecap := httptest.NewRecorder()
	srv.Handler().ServeHTTP(wDecap, reqDecap)

	if wDecap.Code != http.StatusOK {
		t.Fatalf("expected decap status 200, got %d: %s", wDecap.Code, wDecap.Body.String())
	}

	// 4. Validate schema and response
	validateJSONSchema(t, wDecap.Body.Bytes(), decapsResponseSchema)

	var respDecap DecapsResponse
	if err := json.NewDecoder(wDecap.Body).Decode(&respDecap); err != nil {
		t.Fatalf("failed to decode decap response: %v", err)
	}

	if respDecap.SharedSecret.Algorithm != KemAlgorithmDHKEMX25519HKDFSHA256 {
		t.Errorf("expected algorithm %v, got %v", KemAlgorithmDHKEMX25519HKDFSHA256, respDecap.SharedSecret.Algorithm)
	}

	if respDecap.SharedSecret.Secret != base64.StdEncoding.EncodeToString(sharedSecret) {
		t.Errorf("shared secret mismatch.\nExpected: %s\nGot:      %s", base64.StdEncoding.EncodeToString(sharedSecret), respDecap.SharedSecret.Secret)
	}
}

// validateJSONSchema validates that the given JSON data matches the specified schema.
func validateJSONSchema(t *testing.T, data []byte, schema map[string]interface{}) {
	t.Helper()
	var v interface{}
	if err := json.Unmarshal(data, &v); err != nil {
		t.Fatalf("failed to unmarshal JSON: %v", err)
	}
	validateValue(t, v, schema, "")
}

// validateValue is a recursive helper that validates a JSON value against a schema node.
func validateValue(t *testing.T, value interface{}, schema map[string]interface{}, path string) {
	t.Helper()
	if schema == nil {
		return
	}

	schemaType, _ := schema["type"].(string)
	if schemaType == "" {
		return
	}

	switch schemaType {
	case "object":
		valMap, ok := value.(map[string]interface{})
		if !ok {
			t.Errorf("path %s: expected object, got %T", path, value)
			return
		}

		if req, ok := schema["required"].([]interface{}); ok {
			for _, r := range req {
				reqStr, _ := r.(string)
				if _, present := valMap[reqStr]; !present {
					t.Errorf("path %s: missing required field %q", path, reqStr)
				}
			}
		}

		if props, ok := schema["properties"].(map[string]interface{}); ok {
			for k, v := range valMap {
				if propSchema, present := props[k]; present {
					propSchemaMap, _ := propSchema.(map[string]interface{})
					validateValue(t, v, propSchemaMap, path+"."+k)
				} else {
					if addProps, present := schema["additionalProperties"]; present {
						if addPropsBool, ok := addProps.(bool); ok && !addPropsBool {
							t.Errorf("path %s: additional property %q not allowed", path, k)
						}
					}
				}
			}
		}

	case "string":
		strVal, ok := value.(string)
		if !ok {
			t.Errorf("path %s: expected string, got %T", path, value)
			return
		}
		if enum, ok := schema["enum"].([]interface{}); ok {
			found := false
			for _, e := range enum {
				if eStr, ok := e.(string); ok && eStr == strVal {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("path %s: value %q not in enum %v", path, strVal, enum)
			}
		}

	case "integer":
		_, ok := value.(float64)
		if !ok {
			_, okInt := value.(int)
			_, okInt64 := value.(int64)
			if !okInt && !okInt64 {
				t.Errorf("path %s: expected integer (float64), got %T", path, value)
			}
		}

	case "array":
		valArr, ok := value.([]interface{})
		if !ok {
			t.Errorf("path %s: expected array, got %T", path, value)
			return
		}
		if itemsSchema, ok := schema["items"].(map[string]interface{}); ok {
			for i, item := range valArr {
				validateValue(t, item, itemsSchema, fmt.Sprintf("%s[%d]", path, i))
			}
		}

	default:
		t.Errorf("path %s: unknown schema type %q", path, schemaType)
	}
}
