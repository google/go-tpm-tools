package workload_service

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	kpskcc "github.com/google/go-tpm-tools/keymanager/key_protection_service/key_custody_core"
	"github.com/google/uuid"
)

// mockBindingKeyGen implements BindingKeyGenerator for testing.
type mockBindingKeyGen struct {
	uuid   uuid.UUID
	pubKey []byte
	err    error
}

func (m *mockBindingKeyGen) GenerateBindingKeypair(lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return m.uuid, m.pubKey, m.err
}

// mockKEMKeyGen implements KEMKeyGenerator for testing.
type mockKEMKeyGen struct {
	uuid             uuid.UUID
	pubKey           []byte
	err              error
	receivedPubKey   []byte
	receivedLifespan uint64
}

func (m *mockKEMKeyGen) GenerateKEMKeypair(bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	m.receivedPubKey = bindingPubKey
	m.receivedLifespan = lifespanSecs
	return m.uuid, m.pubKey, m.err
}

// mockKEMKeyEnumerator implements KEMKeyEnumerator for testing.
type mockKEMKeyEnumerator struct {
	keys []kpskcc.KEMKeyInfo
	err  error
}

func (m *mockKEMKeyEnumerator) EnumerateKEMKeys() ([]kpskcc.KEMKeyInfo, error) {
	return m.keys, m.err
}

func validGenerateBody() []byte {
	body, _ := json.Marshal(GenerateKemRequest{
		Algorithm:              KemAlgorithmDHKEMX25519HKDFSHA256,
		KeyProtectionMechanism: KeyProtectionMechanismVM,
		Lifespan:               ProtoDuration{Seconds: 3600},
	})
	return body
}

func TestHandleGenerateKemSuccess(t *testing.T) {
	bindingUUID := uuid.New()
	kemUUID := uuid.New()
	bindingPubKey := make([]byte, 32)
	for i := range bindingPubKey {
		bindingPubKey[i] = byte(i)
	}
	kemPubKey := make([]byte, 32)
	for i := range kemPubKey {
		kemPubKey[i] = byte(i + 100)
	}

	kemGen := &mockKEMKeyGen{uuid: kemUUID, pubKey: kemPubKey}
	srv := NewServer(
		&mockBindingKeyGen{uuid: bindingUUID, pubKey: bindingPubKey},
		kemGen,
		&mockKEMKeyEnumerator{},
	)

	req := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_kem", bytes.NewReader(validGenerateBody()))
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
	if resp.KeyHandle.Handle != kemUUID.String() {
		t.Fatalf("expected KEM UUID %s, got %s", kemUUID, resp.KeyHandle.Handle)
	}

	// Verify the binding public key was passed to KEM generator.
	if len(kemGen.receivedPubKey) != 32 {
		t.Fatalf("expected 32-byte binding pub key passed to KEM gen, got %d", len(kemGen.receivedPubKey))
	}
	for i, b := range kemGen.receivedPubKey {
		if b != byte(i) {
			t.Fatalf("binding pub key mismatch at index %d", i)
		}
	}

	// Verify lifespanSecs was forwarded.
	if kemGen.receivedLifespan != 3600 {
		t.Fatalf("expected lifespanSecs 3600, got %d", kemGen.receivedLifespan)
	}

	// Verify the KEM → Binding mapping was stored.
	mappedBinding, ok := srv.LookupBindingUUID(kemUUID)
	if !ok {
		t.Fatal("expected KEM UUID to be in kemToBindingMap")
	}
	if mappedBinding != bindingUUID {
		t.Fatalf("expected mapped binding UUID %s, got %s", bindingUUID, mappedBinding)
	}
}

func TestHandleGenerateKemInvalidMethod(t *testing.T) {
	srv := NewServer(
		&mockBindingKeyGen{pubKey: make([]byte, 32)},
		&mockKEMKeyGen{pubKey: make([]byte, 32)},
		&mockKEMKeyEnumerator{},
	)

	req := httptest.NewRequest(http.MethodGet, "/v1/keys:generate_kem", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

func TestHandleGenerateKemBadRequest(t *testing.T) {
	srv := NewServer(
		&mockBindingKeyGen{uuid: uuid.New(), pubKey: make([]byte, 32)},
		&mockKEMKeyGen{uuid: uuid.New(), pubKey: make([]byte, 32)},
		&mockKEMKeyEnumerator{},
	)

	tests := []struct {
		name string
		body GenerateKemRequest
	}{
		{
			name: "unsupported algorithm",
			body: GenerateKemRequest{Algorithm: KemAlgorithm(99), KeyProtectionMechanism: KeyProtectionMechanismVM, Lifespan: ProtoDuration{Seconds: 3600}},
		},
		{
			name: "unsupported key protection mechanism",
			body: GenerateKemRequest{Algorithm: KemAlgorithmDHKEMX25519HKDFSHA256, KeyProtectionMechanism: KeyProtectionMechanism(99), Lifespan: ProtoDuration{Seconds: 3600}},
		},
		{
			name: "zero lifespan",
			body: GenerateKemRequest{Algorithm: KemAlgorithmDHKEMX25519HKDFSHA256, KeyProtectionMechanism: KeyProtectionMechanismVM, Lifespan: ProtoDuration{Seconds: 0}},
		},
		{
			name: "missing algorithm (defaults to 0)",
			body: GenerateKemRequest{KeyProtectionMechanism: KeyProtectionMechanismVM, Lifespan: ProtoDuration{Seconds: 3600}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := json.Marshal(tc.body)
			req := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_kem", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected status 400, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestHandleGenerateKemBadJSON(t *testing.T) {
	srv := NewServer(
		&mockBindingKeyGen{pubKey: make([]byte, 32)},
		&mockKEMKeyGen{pubKey: make([]byte, 32)},
		&mockKEMKeyEnumerator{},
	)

	badBodies := []struct {
		name string
		body string
	}{
		{"not json", "not json"},
		{"lifespan as integer", `{"algorithm":1,"key_protection_mechanism":2,"lifespan":3600}`},
		{"lifespan missing s suffix", `{"algorithm":1,"key_protection_mechanism":2,"lifespan":"3600"}`},
		{"lifespan negative", `{"algorithm":1,"key_protection_mechanism":2,"lifespan":"-1s"}`},
	}

	for _, tc := range badBodies {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_kem", bytes.NewReader([]byte(tc.body)))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected status 400, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestHandleGenerateKemBindingGenError(t *testing.T) {
	srv := NewServer(
		&mockBindingKeyGen{err: fmt.Errorf("binding FFI error")},
		&mockKEMKeyGen{pubKey: make([]byte, 32)},
		&mockKEMKeyEnumerator{},
	)

	req := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_kem", bytes.NewReader(validGenerateBody()))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestHandleGenerateKemKEMGenError(t *testing.T) {
	srv := NewServer(
		&mockBindingKeyGen{uuid: uuid.New(), pubKey: make([]byte, 32)},
		&mockKEMKeyGen{err: fmt.Errorf("KEM FFI error")},
		&mockKEMKeyEnumerator{},
	)

	req := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_kem", bytes.NewReader(validGenerateBody()))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestHandleEnumerateKeysEmpty(t *testing.T) {
	srv := NewServer(
		&mockBindingKeyGen{},
		&mockKEMKeyGen{},
		&mockKEMKeyEnumerator{keys: []kpskcc.KEMKeyInfo{}},
	)

	req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp EnumerateKeysResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(resp.KeyInfos) != 0 {
		t.Fatalf("expected 0 key infos, got %d", len(resp.KeyInfos))
	}
}

func TestHandleEnumerateKeysWithKeys(t *testing.T) {
	kem1 := uuid.New()
	kem2 := uuid.New()
	kemPubKey1 := make([]byte, 32)
	kemPubKey2 := make([]byte, 32)
	bindingPubKey1 := make([]byte, 32)
	bindingPubKey2 := make([]byte, 32)
	for i := range kemPubKey1 {
		kemPubKey1[i] = byte(i)
		kemPubKey2[i] = byte(i + 50)
		bindingPubKey1[i] = byte(i + 100)
		bindingPubKey2[i] = byte(i + 150)
	}

	mockEnum := &mockKEMKeyEnumerator{
		keys: []kpskcc.KEMKeyInfo{
			{
				ID:                    kem1,
				KemAlgorithm:          1,
				KdfAlgorithm:          1,
				AeadAlgorithm:         1,
				KEMPubKey:             kemPubKey1,
				BindingPubKey:         bindingPubKey1,
				RemainingLifespanSecs: 3500,
			},
			{
				ID:                    kem2,
				KemAlgorithm:          1,
				KdfAlgorithm:          1,
				AeadAlgorithm:         1,
				KEMPubKey:             kemPubKey2,
				BindingPubKey:         bindingPubKey2,
				RemainingLifespanSecs: 7100,
			},
		},
	}

	srv := NewServer(
		&mockBindingKeyGen{},
		&mockKEMKeyGen{},
		mockEnum,
	)

	req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp EnumerateKeysResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(resp.KeyInfos) != 2 {
		t.Fatalf("expected 2 key infos, got %d", len(resp.KeyInfos))
	}

	// Verify both keys appear (order-independent).
	found := make(map[string]*BoundKEMInfo)
	for _, ki := range resp.KeyInfos {
		if ki.BoundKemInfo == nil {
			t.Fatal("expected non-nil boundKemInfo")
		}
		found[ki.BoundKemInfo.KeyHandle.Handle] = ki.BoundKemInfo
	}

	// Verify key 1.
	info1, ok := found[kem1.String()]
	if !ok {
		t.Fatalf("expected kem1 %s in response", kem1)
	}
	if info1.KemPubKey.Algorithm != KemAlgorithmDHKEMX25519HKDFSHA256 {
		t.Fatalf("expected algorithm %v, got %v", KemAlgorithmDHKEMX25519HKDFSHA256, info1.KemPubKey.Algorithm)
	}
	if info1.KemPubKey.PublicKey != base64.StdEncoding.EncodeToString(kemPubKey1) {
		t.Fatalf("KEM pub key mismatch for kem1")
	}
	if info1.BindingPubKey.PublicKey != base64.StdEncoding.EncodeToString(bindingPubKey1) {
		t.Fatalf("binding pub key mismatch for kem1")
	}
	expectedHPKE := HpkeAlgorithm{
		Kem:  KemAlgorithmDHKEMX25519HKDFSHA256,
		Kdf:  KdfAlgorithmHKDFSHA384,
		Aead: AeadAlgorithmAES256GCM,
	}
	if info1.BindingPubKey.Algorithm != expectedHPKE {
		t.Fatalf("HPKE algorithm mismatch for kem1: expected %v, got %v", expectedHPKE, info1.BindingPubKey.Algorithm)
	}
	if info1.RemainingLifespan.Seconds != 3500 {
		t.Fatalf("expected remaining lifespan 3500, got %d", info1.RemainingLifespan.Seconds)
	}

	// Verify key 2.
	info2, ok := found[kem2.String()]
	if !ok {
		t.Fatalf("expected kem2 %s in response", kem2)
	}
	if info2.RemainingLifespan.Seconds != 7100 {
		t.Fatalf("expected remaining lifespan 7100, got %d", info2.RemainingLifespan.Seconds)
	}
}

func TestHandleEnumerateKeysMethodNotAllowed(t *testing.T) {
	srv := NewServer(
		&mockBindingKeyGen{},
		&mockKEMKeyGen{},
		&mockKEMKeyEnumerator{},
	)

	req := httptest.NewRequest(http.MethodPost, "/v1/keys", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

func TestHandleEnumerateKeysError(t *testing.T) {
	srv := NewServer(
		&mockBindingKeyGen{},
		&mockKEMKeyGen{},
		&mockKEMKeyEnumerator{err: fmt.Errorf("enumerate error")},
	)

	req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleGenerateKemMapUniqueness(t *testing.T) {
	bindingPubKey := make([]byte, 32)

	bindingUUID1 := uuid.New()
	bindingUUID2 := uuid.New()
	kemUUID1 := uuid.New()
	kemUUID2 := uuid.New()

	callCount := 0
	bindingGen := &mockBindingKeyGen{}
	kemGen := &mockKEMKeyGen{}

	srv := NewServer(bindingGen, kemGen, &mockKEMKeyEnumerator{})

	// First call.
	bindingGen.uuid = bindingUUID1
	bindingGen.pubKey = bindingPubKey
	kemGen.uuid = kemUUID1
	kemGen.pubKey = make([]byte, 32)

	req := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_kem", bytes.NewReader(validGenerateBody()))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("call 1: expected status 200, got %d: %s", w.Code, w.Body.String())
	}
	callCount++

	// Second call.
	bindingGen.uuid = bindingUUID2
	kemGen.uuid = kemUUID2

	req = httptest.NewRequest(http.MethodPost, "/v1/keys:generate_kem", bytes.NewReader(validGenerateBody()))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("call 2: expected status 200, got %d: %s", w.Code, w.Body.String())
	}
	callCount++

	// Verify both mappings exist.
	mapped1, ok := srv.LookupBindingUUID(kemUUID1)
	if !ok {
		t.Fatal("expected kemUUID1 in map")
	}
	if mapped1 != bindingUUID1 {
		t.Fatalf("expected binding UUID %s for kem UUID %s, got %s", bindingUUID1, kemUUID1, mapped1)
	}

	mapped2, ok := srv.LookupBindingUUID(kemUUID2)
	if !ok {
		t.Fatal("expected kemUUID2 in map")
	}
	if mapped2 != bindingUUID2 {
		t.Fatalf("expected binding UUID %s for kem UUID %s, got %s", bindingUUID2, kemUUID2, mapped2)
	}

	if callCount != 2 {
		t.Fatalf("expected 2 calls, got %d", callCount)
	}
}
