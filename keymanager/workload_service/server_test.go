package workload_service

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
)

// --- Mocks ---

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

func validGenerateBody() []byte {
	body, _ := json.Marshal(GenerateKemRequest{
		Algorithm:              KemAlgorithmDHKEMX25519HKDFSHA256,
		KeyProtectionMechanism: KeyProtectionMechanismVM,
		Lifespan:               ProtoDuration{Seconds: 3600},
	})
	return body
}

// mockDecapSealer implements DecapSealer for testing.
type mockDecapSealer struct {
	sealEnc         []byte
	sealedCT        []byte
	err             error
	receivedKEMUUID uuid.UUID
	receivedEncKey  []byte
	receivedAAD     []byte
}

func (m *mockDecapSealer) DecapAndSeal(kemUUID uuid.UUID, encapsulatedKey, aad []byte) ([]byte, []byte, error) {
	m.receivedKEMUUID = kemUUID
	m.receivedEncKey = encapsulatedKey
	m.receivedAAD = aad
	return m.sealEnc, m.sealedCT, m.err
}

// mockOpener implements Opener for testing.
type mockOpener struct {
	plaintext    []byte
	err          error
	receivedUUID uuid.UUID
	receivedEnc  []byte
	receivedCT   []byte
	receivedAAD  []byte
}

func (m *mockOpener) Open(bindingUUID uuid.UUID, enc, ciphertext, aad []byte) ([]byte, error) {
	m.receivedUUID = bindingUUID
	m.receivedEnc = enc
	m.receivedCT = ciphertext
	m.receivedAAD = aad
	return m.plaintext, m.err
}

// noopDecapSealer returns a no-op DecapSealer for tests that don't use it.
func noopDecapSealer() *mockDecapSealer { return &mockDecapSealer{} }

// noopOpener returns a no-op Opener for tests that don't use it.
func noopOpener() *mockOpener { return &mockOpener{} }

// --- /keys:generate tests ---

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
		noopDecapSealer(),
		noopOpener(),
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
		noopDecapSealer(),
		noopOpener(),
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
		noopDecapSealer(),
		noopOpener(),
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
		noopDecapSealer(),
		noopOpener(),
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
		noopDecapSealer(),
		noopOpener(),
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
		noopDecapSealer(),
		noopOpener(),
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

	srv := NewServer(bindingGen, kemGen, noopDecapSealer(), noopOpener())

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

// --- /keys:decaps tests ---

// newDecapsTestServer creates a server pre-populated with a KEM→Binding mapping.
func newDecapsTestServer(kemUUID, bindingUUID uuid.UUID, ds *mockDecapSealer, op *mockOpener) *Server {
	srv := NewServer(
		&mockBindingKeyGen{},
		&mockKEMKeyGen{},
		ds,
		op,
	)
	srv.mu.Lock()
	srv.kemToBindingMap[kemUUID] = bindingUUID
	srv.mu.Unlock()
	return srv
}

func decapsRequestBody(kemUUID uuid.UUID, algo KemAlgorithm, encKey []byte) string {
	return fmt.Sprintf(
		`{"keyHandle":{"handle":"%s"},"ciphertext":{"algorithm":%d,"ciphertext":"%s"}}`,
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

	ds := &mockDecapSealer{sealEnc: sealEnc, sealedCT: sealedCT}
	op := &mockOpener{plaintext: plaintext}
	srv := newDecapsTestServer(kemUUID, bindingUUID, ds, op)

	body := decapsRequestBody(kemUUID, KemAlgorithmDHKEMX25519HKDFSHA256, encKey)
	req := httptest.NewRequest(http.MethodPost, "/v1/keys:decaps", strings.NewReader(body))
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
		t.Fatalf("expected sharedSecret.algorithm=%d, got %d", KemAlgorithmDHKEMX25519HKDFSHA256, resp.SharedSecret.Algorithm)
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
	srv := NewServer(
		&mockBindingKeyGen{},
		&mockKEMKeyGen{},
		noopDecapSealer(),
		noopOpener(),
	)

	req := httptest.NewRequest(http.MethodGet, "/v1/keys:decaps", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

func TestHandleDecapsBadRequestBody(t *testing.T) {
	srv := NewServer(
		&mockBindingKeyGen{},
		&mockKEMKeyGen{},
		noopDecapSealer(),
		noopOpener(),
	)

	req := httptest.NewRequest(http.MethodPost, "/v1/keys:decaps", strings.NewReader("not-json"))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestHandleDecapsInvalidKEMUUID(t *testing.T) {
	srv := NewServer(
		&mockBindingKeyGen{},
		&mockKEMKeyGen{},
		noopDecapSealer(),
		noopOpener(),
	)

	body := `{"keyHandle":{"handle":"not-a-uuid"},"ciphertext":{"algorithm":1,"ciphertext":"AAAA"}}`
	req := httptest.NewRequest(http.MethodPost, "/v1/keys:decaps", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestHandleDecapsKEMKeyNotFound(t *testing.T) {
	kemUUID := uuid.New()
	srv := NewServer(
		&mockBindingKeyGen{},
		&mockKEMKeyGen{},
		noopDecapSealer(),
		noopOpener(),
	)
	// Don't populate kemToBindingMap.

	body := decapsRequestBody(kemUUID, KemAlgorithmDHKEMX25519HKDFSHA256, []byte("enc-key"))
	req := httptest.NewRequest(http.MethodPost, "/v1/keys:decaps", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d: %s", w.Code, w.Body.String())
	}
}

func TestHandleDecapsDecapSealError(t *testing.T) {
	kemUUID := uuid.New()
	bindingUUID := uuid.New()

	ds := &mockDecapSealer{err: fmt.Errorf("decap FFI error")}
	srv := newDecapsTestServer(kemUUID, bindingUUID, ds, noopOpener())

	body := decapsRequestBody(kemUUID, KemAlgorithmDHKEMX25519HKDFSHA256, []byte("enc-key"))
	req := httptest.NewRequest(http.MethodPost, "/v1/keys:decaps", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestHandleDecapsOpenError(t *testing.T) {
	kemUUID := uuid.New()
	bindingUUID := uuid.New()

	ds := &mockDecapSealer{sealEnc: []byte("enc"), sealedCT: []byte("ct")}
	op := &mockOpener{err: fmt.Errorf("open FFI error")}
	srv := newDecapsTestServer(kemUUID, bindingUUID, ds, op)

	body := decapsRequestBody(kemUUID, KemAlgorithmDHKEMX25519HKDFSHA256, []byte("enc-key"))
	req := httptest.NewRequest(http.MethodPost, "/v1/keys:decaps", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestHandleDecapsUnsupportedAlgorithm(t *testing.T) {
	kemUUID := uuid.New()
	bindingUUID := uuid.New()
	srv := newDecapsTestServer(kemUUID, bindingUUID, noopDecapSealer(), noopOpener())

	body := decapsRequestBody(kemUUID, KemAlgorithm(999), []byte("enc-key"))
	req := httptest.NewRequest(http.MethodPost, "/v1/keys:decaps", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}
