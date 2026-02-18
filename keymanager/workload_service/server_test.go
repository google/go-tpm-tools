package workload_service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"

	algorithms "github.com/google/go-tpm-tools/keymanager/km_common/proto"
)

// mockBindingKeyGen implements BindingKeyGenerator for testing.
type mockBindingKeyGen struct {
	uuid   uuid.UUID
	pubKey []byte
	err    error
}

func (m *mockBindingKeyGen) GenerateBindingKeypair(algo *algorithms.HpkeAlgorithm, lifespanSecs uint64) (uuid.UUID, []byte, error) {
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

func (m *mockKEMKeyGen) GenerateKEMKeypair(algo *algorithms.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	m.receivedPubKey = bindingPubKey
	m.receivedLifespan = lifespanSecs
	return m.uuid, m.pubKey, m.err
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
	)

	tests := []struct {
		name string
		body GenerateKemRequest
	}{
		{
			name: "unsupported algorithm",
			body: GenerateKemRequest{Algorithm: KemAlgorithmUnspecified, KeyProtectionMechanism: KeyProtectionMechanismVM, Lifespan: ProtoDuration{Seconds: 3600}},
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

			if tc.name == "unsupported algorithm" {
				var resp map[string]string
				if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				expectedSubstr := "Supported algorithms: DHKEM_X25519_HKDF_SHA256"
				if errMsg, ok := resp["error"]; !ok || !strings.Contains(errMsg, expectedSubstr) {
					t.Errorf("expected error message to contain %q, got %q", expectedSubstr, errMsg)
				}
			}
		})
	}
}

func TestHandleGenerateKemBadJSON(t *testing.T) {
	srv := NewServer(
		&mockBindingKeyGen{pubKey: make([]byte, 32)},
		&mockKEMKeyGen{pubKey: make([]byte, 32)},
	)

	badBodies := []struct {
		name string
		body string
	}{
		{"not json", "not json"},
		{"lifespan as string", `{"algorithm":1,"key_protection_mechanism":2,"lifespan":"3600"}`},
		{"lifespan as string with suffix", `{"algorithm":1,"key_protection_mechanism":2,"lifespan":"3600s"}`},
		{"lifespan negative", `{"algorithm":1,"key_protection_mechanism":2,"lifespan":-1}`},
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
	)

	req := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_kem", bytes.NewReader(validGenerateBody()))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestHandleGenerateKemFlexibleLifespan(t *testing.T) {
	srv := NewServer(
		&mockBindingKeyGen{uuid: uuid.New(), pubKey: make([]byte, 32)},
		&mockKEMKeyGen{uuid: uuid.New(), pubKey: make([]byte, 32)},
	)

	tests := []struct {
		name     string
		body     string
		expected uint64
	}{
		{
			name:     "integer seconds",
			body:     `{"algorithm":"DHKEM_X25519_HKDF_SHA256","key_protection_mechanism":"KEY_PROTECTION_VM","lifespan":3600}`,
			expected: 3600,
		},
		{
			name:     "float seconds",
			body:     `{"algorithm":"DHKEM_X25519_HKDF_SHA256","key_protection_mechanism":"KEY_PROTECTION_VM","lifespan":1.5}`,
			expected: 1, // Truncated to 1
		},
		{
			name:     "float seconds round down",
			body:     `{"algorithm":"DHKEM_X25519_HKDF_SHA256","key_protection_mechanism":"KEY_PROTECTION_VM","lifespan":3600.9}`,
			expected: 3600,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_kem", bytes.NewReader([]byte(tc.body)))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestHandleGenerateKemKEMGenError(t *testing.T) {
	srv := NewServer(
		&mockBindingKeyGen{uuid: uuid.New(), pubKey: make([]byte, 32)},
		&mockKEMKeyGen{err: fmt.Errorf("KEM FFI error")},
	)

	req := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_kem", bytes.NewReader(validGenerateBody()))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
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

	srv := NewServer(bindingGen, kemGen)

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

func TestKemAlgorithmToHpkeAlgorithm(t *testing.T) {
	tests := []struct {
		input    KemAlgorithm
		want     *algorithms.HpkeAlgorithm
		wantErr  bool
	}{
		{
			input: KemAlgorithmDHKEMX25519HKDFSHA256,
			want: &algorithms.HpkeAlgorithm{
				Kem:  algorithms.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
				Kdf:  algorithms.KdfAlgorithm_KDF_ALGORITHM_HKDF_SHA256,
				Aead: algorithms.AeadAlgorithm_AEAD_ALGORITHM_AES_256_GCM,
			},
			wantErr: false,
		},
		{
			input:   KemAlgorithmUnspecified,
			want:    nil,
			wantErr: true,
		},
		{
			input:   KemAlgorithm(999),
			want:    nil,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		got, err := kemAlgorithmToHpkeAlgorithm(tc.input)
		if (err != nil) != tc.wantErr {
			t.Errorf("kemAlgorithmToHpkeAlgorithm(%v) error = %v, wantErr %v", tc.input, err, tc.wantErr)
			continue
		}
		if !tc.wantErr {
			if got.Kem != tc.want.Kem || got.Kdf != tc.want.Kdf || got.Aead != tc.want.Aead {
				t.Errorf("kemAlgorithmToHpkeAlgorithm(%v) = %v, want %v", tc.input, got, tc.want)
			}
		}
	}
}
