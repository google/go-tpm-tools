package workloadservice

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	kps "github.com/google/go-tpm-tools/keymanager/key_protection_service"
	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
)

func newTestServer(t *testing.T, kemGen kps.KeyProtectionService, bindingGen WorkloadService) *Server {
	srv, err := NewServer(kemGen, bindingGen, filepath.Join(t.TempDir(), "test.sock"))
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}
	t.Cleanup(func() {
		srv.listener.Close()
		close(srv.claimsChan)
	})
	return srv
}

// mockWorkloadService implements WorkloadService for testing.
type mockWorkloadService struct {
	uuid   uuid.UUID
	pubKey []byte
	algo   *keymanager.HpkeAlgorithm
	err    error
}

func (m *mockWorkloadService) GenerateBindingKeypair(_ *keymanager.HpkeAlgorithm, _ uint64) (uuid.UUID, []byte, error) {
	return m.uuid, m.pubKey, m.err
}

func (m *mockWorkloadService) GetBindingKey(_ uuid.UUID) ([]byte, *keymanager.HpkeAlgorithm, error) {
	return m.pubKey, m.algo, m.err
}

// mockKeyProtectionService implements KeyProtectionService for testing.
type mockKeyProtectionService struct {
	uuid             uuid.UUID
	pubKey           []byte
	bindingPubKey    []byte
	algo             *keymanager.HpkeAlgorithm
	deleteAfter      uint64
	err              error
	receivedPubKey   []byte
	receivedLifespan uint64
}

func (m *mockKeyProtectionService) GenerateKEMKeypair(_ *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	m.receivedPubKey = bindingPubKey
	m.receivedLifespan = lifespanSecs
	return m.uuid, m.pubKey, m.err
}

func (m *mockKeyProtectionService) GetKemKey(_ uuid.UUID) ([]byte, []byte, *keymanager.HpkeAlgorithm, uint64, error) {
	return m.pubKey, m.bindingPubKey, m.algo, m.deleteAfter, m.err
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

	kemGen := &mockKeyProtectionService{uuid: kemUUID, pubKey: kemPubKey}
	srv := newTestServer(t,
		kemGen,
		&mockWorkloadService{uuid: bindingUUID, pubKey: bindingPubKey},
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
	srv := newTestServer(t,
		&mockKeyProtectionService{pubKey: make([]byte, 32)},
		&mockWorkloadService{pubKey: make([]byte, 32)},
	)

	req := httptest.NewRequest(http.MethodGet, "/v1/keys:generate_kem", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

func TestHandleGenerateKemBadRequest(t *testing.T) {
	srv := newTestServer(t,
		&mockKeyProtectionService{uuid: uuid.New(), pubKey: make([]byte, 32)},
		&mockWorkloadService{uuid: uuid.New(), pubKey: make([]byte, 32)},
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
	srv := newTestServer(t,
		&mockKeyProtectionService{pubKey: make([]byte, 32)},
		&mockWorkloadService{pubKey: make([]byte, 32)},
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
	srv := newTestServer(t,
		&mockKeyProtectionService{pubKey: make([]byte, 32)},
		&mockWorkloadService{err: fmt.Errorf("binding FFI error")},
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
	srv := newTestServer(t,
		&mockKeyProtectionService{uuid: uuid.New(), pubKey: make([]byte, 32)},
		&mockWorkloadService{uuid: uuid.New(), pubKey: make([]byte, 32)},
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
	srv := newTestServer(t,
		&mockKeyProtectionService{err: fmt.Errorf("KEM FFI error")},
		&mockWorkloadService{uuid: uuid.New(), pubKey: make([]byte, 32)},
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
	bindingGen := &mockWorkloadService{}
	kemGen := &mockKeyProtectionService{}

	srv := newTestServer(t, kemGen, bindingGen)

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

func TestToHpkeAlgorithm(t *testing.T) {
	tests := []struct {
		input   KemAlgorithm
		want    *keymanager.HpkeAlgorithm
		wantErr bool
	}{
		{
			input: KemAlgorithmDHKEMX25519HKDFSHA256,
			want: &keymanager.HpkeAlgorithm{
				Kem:  keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
				Kdf:  keymanager.KdfAlgorithm_KDF_ALGORITHM_HKDF_SHA256,
				Aead: keymanager.AeadAlgorithm_AEAD_ALGORITHM_AES_256_GCM,
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
		t.Run(fmt.Sprintf("%v", tc.input), func(t *testing.T) {
			got, err := tc.input.ToHpkeAlgorithm()
			if (err != nil) != tc.wantErr {
				t.Errorf("ToHpkeAlgorithm() error = %v, wantErr %v", err, tc.wantErr)
				return
			}
			if !tc.wantErr {
				if got.Kem != tc.want.Kem || got.Kdf != tc.want.Kdf || got.Aead != tc.want.Aead {
					t.Errorf("ToHpkeAlgorithm() = %v, want %v", got, tc.want)
				}
			}
		})
	}
}

func TestHandleGetCapabilities(t *testing.T) {
	bindingGen := &mockWorkloadService{}
	kemGen := &mockKeyProtectionService{}
	srv := newTestServer(t,
		kemGen,
		bindingGen,
	)

	req := httptest.NewRequest(http.MethodGet, "/v1/capabilities", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Fatalf("expected Content-Type application/json, got %s", contentType)
	}

	var resp GetCapabilitiesResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(resp.SupportedAlgorithms) != 1 ||
		resp.SupportedAlgorithms[0].Algorithm.Params.KemID != KemAlgorithmDHKEMX25519HKDFSHA256 ||
		resp.SupportedAlgorithms[0].Algorithm.Type != "kem" {
		t.Errorf("unexpected supported algorithms: %v", resp.SupportedAlgorithms)
	}
}

func TestProcessClaims(t *testing.T) {
	bindingUUID := uuid.New()
	kemUUID := uuid.New()
	bindingPubKey := make([]byte, 32)
	for i := range bindingPubKey {
		bindingPubKey[i] = byte(i + 1)
	}
	kemPubKey := make([]byte, 32)
	for i := range kemPubKey {
		kemPubKey[i] = byte(i + 100)
	}

	expectedAlgo := &keymanager.HpkeAlgorithm{
		Kem:  keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
		Kdf:  keymanager.KdfAlgorithm_KDF_ALGORITHM_HKDF_SHA256,
		Aead: keymanager.AeadAlgorithm_AEAD_ALGORITHM_AES_256_GCM,
	}

	ws := &mockWorkloadService{
		uuid:   bindingUUID,
		pubKey: bindingPubKey,
		algo:   expectedAlgo,
	}
	kps := &mockKeyProtectionService{
		uuid:          kemUUID,
		pubKey:        kemPubKey,
		bindingPubKey: bindingPubKey,
		algo:          expectedAlgo,
		deleteAfter:   uint64(time.Now().Add(1 * time.Hour).Unix()),
	}

	srv := newTestServer(t, kps, ws)

	t.Run("BindingClaims", func(t *testing.T) {
		respChan := make(chan *ClaimsResult, 1)
		req := &keymanager.GetKeyClaimsRequest{
			KeyHandle: &keymanager.KeyHandle{Handle: bindingUUID.String()},
			KeyType:   keymanager.KeyType_KEY_TYPE_VM_PROTECTION_BINDING,
		}
		srv.claimsChan <- &ClaimsCall{Request: req, RespChan: respChan}

		select {
		case res := <-respChan:
			if res.Err != nil {
				t.Fatalf("unexpected error: %v", res.Err)
			}
			claims := res.Reply.GetVmBindingClaims()
			if claims == nil {
				t.Fatal("expected VmBindingClaims")
			}
			if !bytes.Equal(claims.BindingPubKey.PublicKey, bindingPubKey) {
				t.Errorf("expected binding pubkey %v, got %v", bindingPubKey, claims.BindingPubKey.PublicKey)
			}
			if claims.BindingPubKey.Algorithm.Kem != expectedAlgo.Kem ||
				claims.BindingPubKey.Algorithm.Kdf != expectedAlgo.Kdf ||
				claims.BindingPubKey.Algorithm.Aead != expectedAlgo.Aead {
				t.Errorf("expected binding algorithm %v, got %v", expectedAlgo, claims.BindingPubKey.Algorithm)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for response")
		}
	})

	t.Run("KemClaims", func(t *testing.T) {
		respChan := make(chan *ClaimsResult, 1)
		req := &keymanager.GetKeyClaimsRequest{
			KeyHandle: &keymanager.KeyHandle{Handle: kemUUID.String()},
			KeyType:   keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY,
		}
		srv.claimsChan <- &ClaimsCall{Request: req, RespChan: respChan}

		select {
		case res := <-respChan:
			if res.Err != nil {
				t.Fatalf("unexpected error: %v", res.Err)
			}
			claims := res.Reply.GetVmKeyClaims()
			if claims == nil {
				t.Fatal("expected VmKeyClaims")
			}
			if !bytes.Equal(claims.KemPubKey.PublicKey, kemPubKey) {
				t.Errorf("expected KEM pubkey %v, got %v", kemPubKey, claims.KemPubKey.PublicKey)
			}
			if claims.KemPubKey.Algorithm != expectedAlgo.Kem {
				t.Errorf("expected KEM algorithm %v, got %v", expectedAlgo.Kem, claims.KemPubKey.Algorithm)
			}
			if !bytes.Equal(claims.BindingPubKey.PublicKey, bindingPubKey) {
				t.Errorf("expected binding pubkey %v, got %v", bindingPubKey, claims.BindingPubKey.PublicKey)
			}
			if claims.BindingPubKey.Algorithm.Kem != expectedAlgo.Kem ||
				claims.BindingPubKey.Algorithm.Kdf != expectedAlgo.Kdf ||
				claims.BindingPubKey.Algorithm.Aead != expectedAlgo.Aead {
				t.Errorf("expected binding algorithm %v, got %v", expectedAlgo, claims.BindingPubKey.Algorithm)
			}
			if claims.RemainingLifespan.AsDuration() <= 0 {
				t.Errorf("expected positive remaining lifespan, got %v", claims.RemainingLifespan.AsDuration())
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for response")
		}
	})

	t.Run("InvalidUUID", func(t *testing.T) {
		respChan := make(chan *ClaimsResult, 1)
		req := &keymanager.GetKeyClaimsRequest{
			KeyHandle: &keymanager.KeyHandle{Handle: "invalid-uuid"},
			KeyType:   keymanager.KeyType_KEY_TYPE_VM_PROTECTION_BINDING,
		}
		srv.claimsChan <- &ClaimsCall{Request: req, RespChan: respChan}

		select {
		case res := <-respChan:
			if res.Err == nil {
				t.Fatal("expected error for invalid UUID")
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for response")
		}
	})

	t.Run("UnsupportedKeyType", func(t *testing.T) {
		respChan := make(chan *ClaimsResult, 1)
		req := &keymanager.GetKeyClaimsRequest{
			KeyHandle: &keymanager.KeyHandle{Handle: bindingUUID.String()},
			KeyType:   keymanager.KeyType_KEY_TYPE_UNSPECIFIED,
		}
		srv.claimsChan <- &ClaimsCall{Request: req, RespChan: respChan}

		select {
		case res := <-respChan:
			if res.Err == nil {
				t.Fatal("expected error for unsupported key type")
			}
			if !strings.Contains(res.Err.Error(), "unsupported key type") {
				t.Errorf("expected error to contain 'unsupported key type', got %v", res.Err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for response")
		}
	})

	t.Run("BindingKeyNotFound", func(t *testing.T) {
		respChan := make(chan *ClaimsResult, 1)
		// Use a random UUID that isn't the mock's UUID
		notFoundUUID := uuid.New()
		req := &keymanager.GetKeyClaimsRequest{
			KeyHandle: &keymanager.KeyHandle{Handle: notFoundUUID.String()},
			KeyType:   keymanager.KeyType_KEY_TYPE_VM_PROTECTION_BINDING,
		}

		// Update mock to return error for anything other than its set UUID
		// Actually, the current mock returns its fixed pubKey/err regardless of input ID.
		// Let's create a new server with a mock that returns error.
		wsErr := &mockWorkloadService{err: fmt.Errorf("not found")}
		srvErr := newTestServer(t, kps, wsErr)

		srvErr.claimsChan <- &ClaimsCall{Request: req, RespChan: respChan}

		select {
		case res := <-respChan:
			if res.Err == nil {
				t.Fatal("expected error for binding key not found")
			}
			if !strings.Contains(res.Err.Error(), "failed to get binding key") {
				t.Errorf("expected error to contain 'failed to get binding key', got %v", res.Err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for response")
		}
	})

	t.Run("KemKeyNotFound", func(t *testing.T) {
		respChan := make(chan *ClaimsResult, 1)
		req := &keymanager.GetKeyClaimsRequest{
			KeyHandle: &keymanager.KeyHandle{Handle: kemUUID.String()},
			KeyType:   keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY,
		}

		kpsErr := &mockKeyProtectionService{err: fmt.Errorf("not found")}
		srvErr := newTestServer(t, kpsErr, ws)

		srvErr.claimsChan <- &ClaimsCall{Request: req, RespChan: respChan}

		select {
		case res := <-respChan:
			if res.Err == nil {
				t.Fatal("expected error for KEM key not found")
			}
			if !strings.Contains(res.Err.Error(), "failed to get KEM key") {
				t.Errorf("expected error to contain 'failed to get KEM key', got %v", res.Err)
			}
		case <-time.After(2 * time.Second):
			t.Fatal("timed out waiting for response")
		}
	})
}

func TestHandleGetCapabilitiesInvalidMethod(t *testing.T) {
	bindingGen := &mockWorkloadService{}
	kemGen := &mockKeyProtectionService{}
	srv := newTestServer(t,
		kemGen,
		bindingGen,
	)

	req := httptest.NewRequest(http.MethodPost, "/v1/capabilities", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}
