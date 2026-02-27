package workloadservice

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/uuid"

	keymanager "github.com/google/go-tpm-tools/keymanager/km_common/proto"
)

func newTestServer(t *testing.T, kemGen KeyProtectionService, bindingGen WorkloadService) *Server {
	srv, err := NewServer(kemGen, bindingGen, filepath.Join(t.TempDir(), "test.sock"))
	if err != nil {
		t.Fatalf("failed to create test server: %v", err)
	}
	return srv
}

// mockWorkloadService implements WorkloadService for testing.
type mockWorkloadService struct {
	uuid         uuid.UUID
	pubKey       []byte
	err          error
	plaintext    []byte
	receivedUUID uuid.UUID
	receivedEnc  []byte
	receivedCT   []byte
	receivedAAD  []byte
}

func (m *mockWorkloadService) GenerateBindingKeypair(_ *keymanager.HpkeAlgorithm, _ uint64) (uuid.UUID, []byte, error) {
	return m.uuid, m.pubKey, m.err
}

func (m *mockWorkloadService) Open(bindingUUID uuid.UUID, enc, ciphertext, aad []byte) ([]byte, error) {
	m.receivedUUID = bindingUUID
	m.receivedEnc = enc
	m.receivedCT = ciphertext
	m.receivedAAD = aad
	return m.plaintext, m.err
}

// mockKeyProtectionService implements KeyProtectionService for testing.
type mockKeyProtectionService struct {
	uuid             uuid.UUID
	pubKey           []byte
	err              error
	receivedPubKey   []byte
	receivedLifespan uint64
	sealEnc          []byte
	sealedCT         []byte
	receivedKEMUUID  uuid.UUID
	receivedEncKey   []byte
	receivedAAD      []byte
}

func (m *mockKeyProtectionService) GenerateKEMKeypair(_ *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	m.receivedPubKey = bindingPubKey
	m.receivedLifespan = lifespanSecs
	return m.uuid, m.pubKey, m.err
}

func (m *mockKeyProtectionService) DecapAndSeal(kemUUID uuid.UUID, encapsulatedKey, aad []byte) ([]byte, []byte, error) {
	m.receivedKEMUUID = kemUUID
	m.receivedEncKey = encapsulatedKey
	m.receivedAAD = aad
	return m.sealEnc, m.sealedCT, m.err
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

// --- /keys:decap tests ---

// newDecapsTestServer creates a server pre-populated with a KEM→Binding mapping.
func newDecapsTestServer(t *testing.T, kemUUID, bindingUUID uuid.UUID, ds *mockKeyProtectionService, op *mockWorkloadService) *Server {
	srv := newTestServer(t, ds, op)
	srv.mu.Lock()
	srv.kemToBindingMap[kemUUID] = bindingUUID
	srv.mu.Unlock()
	return srv
}

func decapsRequestBody(kemUUID uuid.UUID, algo KemAlgorithm, encKey []byte) string {
	return fmt.Sprintf(
		`{"key_handle":{"handle":"%s"},"ciphertext":{"algorithm":"%s","ciphertext":"%s"}}`,
		kemUUID.String(),
		algo,
		base64.StdEncoding.EncodeToString(encKey),
	)
}

func TestHandleDecapsSuccess(t *testing.T) {
	kemUUID := uuid.New()
	bindingUUID := uuid.New()
	encKey := []byte("test-encapsulated-key-32-bytes!!")
	sealEnc := []byte("seal-encapsulated-key-32-bytes!!")
	sealedCT := []byte("sealed-ciphertext-48-bytes-with-tag!!!!!!!!!!!!!!")
	plaintext := []byte("shared-secret-32-bytes-value!!!!") // 32 bytes
	expectedAAD := decapsAADContext(kemUUID, KemAlgorithmDHKEMX25519HKDFSHA256)

	ds := &mockKeyProtectionService{sealEnc: sealEnc, sealedCT: sealedCT}
	op := &mockWorkloadService{plaintext: plaintext}
	srv := newDecapsTestServer(t, kemUUID, bindingUUID, ds, op)

	body := decapsRequestBody(kemUUID, KemAlgorithmDHKEMX25519HKDFSHA256, encKey)
	req := httptest.NewRequest(http.MethodPost, "/v1/keys:decap", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp DecapsResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.SharedSecret.Algorithm != KemAlgorithmDHKEMX25519HKDFSHA256 {
		t.Fatalf("expected shared_secret.algorithm=%d, got %d", KemAlgorithmDHKEMX25519HKDFSHA256, resp.SharedSecret.Algorithm)
	}

	decoded, err := base64.StdEncoding.DecodeString(resp.SharedSecret.Secret)
	if err != nil {
		t.Fatalf("failed to base64-decode shared secret: %v", err)
	}
	if string(decoded) != string(plaintext) {
		t.Fatalf("expected plaintext %q, got %q", plaintext, decoded)
	}

	// Verify DecapSealer received correct args.
	if ds.receivedKEMUUID != kemUUID {
		t.Fatalf("expected DecapSealer to receive KEM UUID %s, got %s", kemUUID, ds.receivedKEMUUID)
	}
	if string(ds.receivedEncKey) != string(encKey) {
		t.Fatalf("expected DecapSealer to receive enc key %q, got %q", encKey, ds.receivedEncKey)
	}
	if string(ds.receivedAAD) != string(expectedAAD) {
		t.Fatalf("expected DecapSealer to receive AAD %q, got %q", expectedAAD, ds.receivedAAD)
	}

	// Verify Opener received correct args.
	if op.receivedUUID != bindingUUID {
		t.Fatalf("expected Opener to receive binding UUID %s, got %s", bindingUUID, op.receivedUUID)
	}
	if string(op.receivedEnc) != string(sealEnc) {
		t.Fatalf("expected Opener to receive enc %q, got %q", sealEnc, op.receivedEnc)
	}
	if string(op.receivedCT) != string(sealedCT) {
		t.Fatalf("expected Opener to receive CT %q, got %q", sealedCT, op.receivedCT)
	}
	if string(op.receivedAAD) != string(expectedAAD) {
		t.Fatalf("expected Opener to receive AAD %q, got %q", expectedAAD, op.receivedAAD)
	}
}

func TestHandleDecapsMethodNotAllowed(t *testing.T) {
	srv := newTestServer(t, &mockKeyProtectionService{}, &mockWorkloadService{})

	req := httptest.NewRequest(http.MethodGet, "/v1/keys:decap", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

func TestHandleDecapsBadRequestBody(t *testing.T) {
	srv := newTestServer(t, &mockKeyProtectionService{}, &mockWorkloadService{})

	req := httptest.NewRequest(http.MethodPost, "/v1/keys:decap", strings.NewReader("not-json"))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestHandleDecapsInvalidKEMUUID(t *testing.T) {
	srv := newTestServer(t, &mockKeyProtectionService{}, &mockWorkloadService{})

	body := `{"key_handle":{"handle":"not-a-uuid"},"ciphertext":{"algorithm":1,"ciphertext":"AAAA"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/keys:decap", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestHandleDecapsKEMKeyNotFound(t *testing.T) {
	kemUUID := uuid.New()
	srv := newTestServer(t, &mockKeyProtectionService{}, &mockWorkloadService{})
	// Don't populate kemToBindingMap.

	body := decapsRequestBody(kemUUID, KemAlgorithmDHKEMX25519HKDFSHA256, []byte("enc-key"))
	req := httptest.NewRequest(http.MethodPost, "/v1/keys:decap", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleDecapsDecapSealError(t *testing.T) {
	kemUUID := uuid.New()
	bindingUUID := uuid.New()

	ds := &mockKeyProtectionService{err: fmt.Errorf("decap FFI error")}
	srv := newDecapsTestServer(t, kemUUID, bindingUUID, ds, &mockWorkloadService{})

	body := decapsRequestBody(kemUUID, KemAlgorithmDHKEMX25519HKDFSHA256, []byte("enc-key"))
	req := httptest.NewRequest(http.MethodPost, "/v1/keys:decap", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestHandleDecapsOpenError(t *testing.T) {
	kemUUID := uuid.New()
	bindingUUID := uuid.New()

	ds := &mockKeyProtectionService{sealEnc: []byte("enc"), sealedCT: []byte("ct")}
	op := &mockWorkloadService{err: fmt.Errorf("open FFI error")}
	srv := newDecapsTestServer(t, kemUUID, bindingUUID, ds, op)

	body := decapsRequestBody(kemUUID, KemAlgorithmDHKEMX25519HKDFSHA256, []byte("enc-key"))
	req := httptest.NewRequest(http.MethodPost, "/v1/keys:decap", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestHandleDecapsUnsupportedAlgorithm(t *testing.T) {
	kemUUID := uuid.New()
	bindingUUID := uuid.New()
	srv := newDecapsTestServer(t, kemUUID, bindingUUID, &mockKeyProtectionService{}, &mockWorkloadService{})

	body := decapsRequestBody(kemUUID, KemAlgorithm(999), []byte("enc-key"))
	req := httptest.NewRequest(http.MethodPost, "/v1/keys:decap", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}
