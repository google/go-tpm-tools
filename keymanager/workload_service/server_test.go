package workloadservice

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	kpskcc "github.com/google/go-tpm-tools/keymanager/key_protection_service/key_custody_core"
	api "github.com/google/go-tpm-tools/keymanager/workload_service/proto"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

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
	uuid          uuid.UUID
	pubKey        []byte
	algo          *keymanager.HpkeAlgorithm
	err           error
	destroyErr    error
	destroyedUUID uuid.UUID
	plaintext     []byte
	receivedUUID  uuid.UUID
	receivedEnc   []byte
	receivedCT    []byte
	receivedAAD   []byte
}

func (m *mockWorkloadService) GenerateBindingKeypair(_ *keymanager.HpkeAlgorithm, _ uint64) (uuid.UUID, []byte, error) {
	return m.uuid, m.pubKey, m.err
}

func (m *mockWorkloadService) DestroyBindingKey(bindingUUID uuid.UUID) error {
	m.destroyedUUID = bindingUUID
	return m.destroyErr
}

func (m *mockWorkloadService) Open(bindingUUID uuid.UUID, enc, ciphertext, aad []byte) ([]byte, error) {
	m.receivedUUID = bindingUUID
	m.receivedEnc = enc
	m.receivedCT = ciphertext
	m.receivedAAD = aad
	return m.plaintext, m.err
}

func (m *mockWorkloadService) GetBindingKey(_ uuid.UUID) ([]byte, *keymanager.HpkeAlgorithm, error) {
	return m.pubKey, m.algo, m.err
}

// mockKeyProtectionService implements KeyProtectionService for testing.
type mockKeyProtectionService struct {
	uuid                  uuid.UUID
	pubKey                []byte
	bindingPubKey         []byte
	algo                  *keymanager.HpkeAlgorithm
	remainingLifespanSecs uint64
	err                   error
	destroyErr            error
	destroyedUUID         uuid.UUID
	receivedPubKey        []byte
	receivedLifespan      uint64
	sealEnc               []byte
	sealedCT              []byte
	receivedKEMUUID       uuid.UUID
	receivedEncKey        []byte
	receivedAAD           []byte
	enumeratedKeys        []kpskcc.KEMKeyInfo
	enumerateErr          error
}

func (m *mockKeyProtectionService) GenerateKEMKeypair(_ *keymanager.HpkeAlgorithm, bindingPubKey []byte, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	m.receivedPubKey = bindingPubKey
	m.receivedLifespan = lifespanSecs
	return m.uuid, m.pubKey, m.err
}

func (m *mockKeyProtectionService) EnumerateKEMKeys(_, _ int) ([]kpskcc.KEMKeyInfo, bool, error) {
	return m.enumeratedKeys, false, m.enumerateErr
}

func (m *mockKeyProtectionService) DestroyKEMKey(kemUUID uuid.UUID) error {
	m.destroyedUUID = kemUUID
	return m.destroyErr
}

func (m *mockKeyProtectionService) DecapAndSeal(kemUUID uuid.UUID, encapsulatedKey, aad []byte) ([]byte, []byte, error) {
	m.receivedKEMUUID = kemUUID
	m.receivedEncKey = encapsulatedKey
	m.receivedAAD = aad
	return m.sealEnc, m.sealedCT, m.err
}

func (m *mockKeyProtectionService) GetKEMKey(_ uuid.UUID) ([]byte, []byte, *keymanager.HpkeAlgorithm, uint64, error) {
	return m.pubKey, m.bindingPubKey, m.algo, m.remainingLifespanSecs, m.err
}

func validGenerateBody() []byte {
	body, _ := protojson.MarshalOptions{EmitUnpopulated: true, UseProtoNames: true}.Marshal(&api.GenerateKeyRequest{
		Algorithm: &keymanager.AlgorithmDetails{
			Type: "kem",
			Params: &keymanager.AlgorithmParams{
				Params: &keymanager.AlgorithmParams_KemId{
					KemId: keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
				},
			},
		},
		Lifespan: 3600,
	})
	return body
}

func assertProtoJSONRoundTrip(t *testing.T, want, got proto.Message) {
	t.Helper()

	body, err := protojson.MarshalOptions{EmitUnpopulated: true, UseProtoNames: true}.Marshal(want)
	if err != nil {
		t.Fatalf("protojson.Marshal() failed: %v", err)
	}

	if err := protojson.Unmarshal(body, got); err != nil {
		t.Fatalf("protojson.Unmarshal() failed: %v", err)
	}

	if !proto.Equal(want, got) {
		t.Fatalf("protojson roundtrip mismatch\njson: %s\nwant: %v\ngot: %v", body, want, got)
	}
}

func TestProtoJSONRoundTrips(t *testing.T) {
	tests := []struct {
		name string
		want proto.Message
		got  proto.Message
	}{
		{
			name: "GenerateKeyRequest",
			want: &api.GenerateKeyRequest{
				Algorithm: &keymanager.AlgorithmDetails{
					Type: "kem",
					Params: &keymanager.AlgorithmParams{
						Params: &keymanager.AlgorithmParams_KemId{
							KemId: keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
						},
					},
				},
				Lifespan: 3600,
			},
			got: &api.GenerateKeyRequest{},
		},
		{
			name: "GenerateKeyResponse",
			want: &api.GenerateKeyResponse{
				KeyHandle: &keymanager.KeyHandle{Handle: uuid.NewString()},
				PubKey: &keymanager.PubKeyInfo{
					Algorithm: &keymanager.AlgorithmDetails{
						Type: "kem",
						Params: &keymanager.AlgorithmParams{
							Params: &keymanager.AlgorithmParams_KemId{
								KemId: keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
							},
						},
					},
					PublicKey: []byte{1, 2, 3, 4},
				},
				KeyProtectionMechanism: keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM_EMULATED.String(),
				ExpirationTime:         1742467200,
			},
			got: &api.GenerateKeyResponse{},
		},
		{
			name: "EnumerateKeysResponse",
			want: &api.EnumerateKeysResponse{
				KeyInfos: []*api.KeyInfo{
					{
						KeyHandle: &keymanager.KeyHandle{Handle: uuid.NewString()},
						PubKey: &keymanager.PubKeyInfo{
							Algorithm: &keymanager.AlgorithmDetails{
								Type: "kem",
								Params: &keymanager.AlgorithmParams{
									Params: &keymanager.AlgorithmParams_KemId{
										KemId: keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
									},
								},
							},
							PublicKey: []byte{5, 6, 7, 8},
						},
						KeyProtectionMechanism: keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM_EMULATED.String(),
						ExpirationTime:         1742468200,
					},
				},
			},
			got: &api.EnumerateKeysResponse{},
		},
		{
			name: "DecapsRequest",
			want: &api.DecapsRequest{
				KeyHandle: &keymanager.KeyHandle{Handle: uuid.NewString()},
				Ciphertext: &keymanager.KemCiphertext{
					Algorithm:  keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
					Ciphertext: []byte{9, 10, 11, 12},
				},
			},
			got: &api.DecapsRequest{},
		},
		{
			name: "DecapsResponse",
			want: &api.DecapsResponse{
				SharedSecret: &keymanager.KemSharedSecret{
					Algorithm: keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
					Secret:    []byte{13, 14, 15, 16},
				},
			},
			got: &api.DecapsResponse{},
		},
		{
			name: "GetCapabilitiesResponse",
			want: &api.GetCapabilitiesResponse{
				SupportedAlgorithms: []*keymanager.SupportedAlgorithm{
					{
						Algorithm: &keymanager.AlgorithmDetails{
							Type: "kem",
							Params: &keymanager.AlgorithmParams{
								Params: &keymanager.AlgorithmParams_KemId{
									KemId: keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
								},
							},
						},
					},
				},
			},
			got: &api.GetCapabilitiesResponse{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assertProtoJSONRoundTrip(t, tc.want, tc.got)
		})
	}
}

// --- /keys:generate_kem tests ---

func TestHandleGenerateKeySuccess(t *testing.T) {
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

	req := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_key", bytes.NewReader(validGenerateBody()))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp api.GenerateKeyResponse
	if err := protojson.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.KeyHandle.Handle != kemUUID.String() {
		t.Fatalf("expected KEM UUID %s, got %s", kemUUID, resp.KeyHandle.Handle)
	}
	if !bytes.Equal(resp.PubKey.PublicKey, kemPubKey) {
		t.Fatalf("expected KEM pub key %s, got %s", kemPubKey, resp.PubKey.PublicKey)
	}
	if resp.KeyProtectionMechanism != keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM_EMULATED.String() {
		t.Fatalf("expected %s, got %s", keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM_EMULATED.String(), resp.KeyProtectionMechanism)
	}
	if resp.ExpirationTime <= float64(time.Now().Unix()) {
		t.Fatalf("expected expiration time in the future, got %f", resp.ExpirationTime)
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

func TestHandleGenerateKeyInvalidMethod(t *testing.T) {
	srv := newTestServer(t,
		&mockKeyProtectionService{pubKey: make([]byte, 32)},
		&mockWorkloadService{pubKey: make([]byte, 32)},
	)

	req := httptest.NewRequest(http.MethodGet, "/v1/keys:generate_key", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

func TestHandleGenerateKeyBadRequest(t *testing.T) {
	srv := newTestServer(t,
		&mockKeyProtectionService{uuid: uuid.New(), pubKey: make([]byte, 32)},
		&mockWorkloadService{uuid: uuid.New(), pubKey: make([]byte, 32)},
	)

	tests := []struct {
		name string
		body *api.GenerateKeyRequest
	}{
		{
			name: "unsupported algorithm type",
			body: &api.GenerateKeyRequest{Algorithm: &keymanager.AlgorithmDetails{Type: "mac", Params: &keymanager.AlgorithmParams{Params: &keymanager.AlgorithmParams_KemId{KemId: keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256}}}, Lifespan: 3600},
		},
		{
			name: "unsupported algorithm",
			body: &api.GenerateKeyRequest{Algorithm: &keymanager.AlgorithmDetails{Type: "kem", Params: &keymanager.AlgorithmParams{Params: &keymanager.AlgorithmParams_KemId{KemId: keymanager.KemAlgorithm_KEM_ALGORITHM_UNSPECIFIED}}}, Lifespan: 3600},
		},
		{
			name: "zero lifespan",
			body: &api.GenerateKeyRequest{Algorithm: &keymanager.AlgorithmDetails{Type: "kem", Params: &keymanager.AlgorithmParams{Params: &keymanager.AlgorithmParams_KemId{KemId: keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256}}}, Lifespan: 0},
		},
		{
			name: "missing algorithm (defaults to 0, type empty)",
			body: &api.GenerateKeyRequest{Lifespan: 3600},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			body, _ := protojson.MarshalOptions{EmitUnpopulated: true, UseProtoNames: true}.Marshal(tc.body)
			req := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_key", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected status 400, got %d: %s", w.Code, w.Body.String())
			}

			if tc.name == "unsupported algorithm" {
				var resp map[string]string
				if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
					t.Fatalf("failed to decode response: %v", err)
				}
				expectedSubstr := "Supported algorithms: KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256"
				if errMsg, ok := resp["error"]; !ok || !strings.Contains(errMsg, expectedSubstr) {
					t.Errorf("expected error message to contain %q, got %q", expectedSubstr, errMsg)
				}
			}
		})
	}
}

func TestHandleGenerateKeyBadJSON(t *testing.T) {
	srv := newTestServer(t,
		&mockKeyProtectionService{pubKey: make([]byte, 32)},
		&mockWorkloadService{pubKey: make([]byte, 32)},
	)

	badBodies := []struct {
		name string
		body string
	}{
		{"not json", "not json"},
		{"lifespan as string with suffix", `{"algorithm":{"type":"kem","params":{"kem_id":"KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256"}},"lifespan":"3600s"}`},
		{"lifespan negative", `{"algorithm":{"type":"kem","params":{"kem_id":"KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256"}},"lifespan":-1}`},
		{"lifespan too large", `{"algorithm":{"type":"kem","params":{"kem_id":"KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256"}},"lifespan":9223372036854775808}`},
	}

	for _, tc := range badBodies {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_key", bytes.NewReader([]byte(tc.body)))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)

			if w.Code != http.StatusBadRequest {
				t.Fatalf("expected status 400, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestHandleGenerateKeyBindingGenError(t *testing.T) {
	srv := newTestServer(t,
		&mockKeyProtectionService{pubKey: make([]byte, 32)},
		&mockWorkloadService{err: fmt.Errorf("binding FFI error")},
	)

	req := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_key", bytes.NewReader(validGenerateBody()))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestHandleGenerateKeyFlexibleLifespan(t *testing.T) {
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
			body:     `{"algorithm":{"type":"kem","params":{"kem_id":"KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256"}},"lifespan":3600}`,
			expected: 3600,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_key", bytes.NewReader([]byte(tc.body)))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestHandleGenerateKeyKEMGenError(t *testing.T) {
	srv := newTestServer(t,
		&mockKeyProtectionService{err: fmt.Errorf("KEM FFI error")},
		&mockWorkloadService{uuid: uuid.New(), pubKey: make([]byte, 32)},
	)

	req := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_key", bytes.NewReader(validGenerateBody()))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestHandleGenerateKeyMapUniqueness(t *testing.T) {
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

	req := httptest.NewRequest(http.MethodPost, "/v1/keys:generate_key", bytes.NewReader(validGenerateBody()))
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

	req = httptest.NewRequest(http.MethodPost, "/v1/keys:generate_key", bytes.NewReader(validGenerateBody()))
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

func TestHandleEnumerateKeysEmpty(t *testing.T) {
	srv := newTestServer(t,
		&mockKeyProtectionService{enumeratedKeys: []kpskcc.KEMKeyInfo{}},
		&mockWorkloadService{},
	)

	req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp api.EnumerateKeysResponse
	if err := protojson.Unmarshal(w.Body.Bytes(), &resp); err != nil {
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
	// BindingPubKey no longer used in response
	for i := range kemPubKey1 {
		kemPubKey1[i] = byte(i)
		kemPubKey2[i] = byte(i + 50)
	}

	mockEnumKeys := []kpskcc.KEMKeyInfo{
		{
			ID: kem1,
			Algorithm: &keymanager.HpkeAlgorithm{
				Kem:  keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
				Kdf:  keymanager.KdfAlgorithm_KDF_ALGORITHM_HKDF_SHA256,
				Aead: keymanager.AeadAlgorithm_AEAD_ALGORITHM_AES_256_GCM,
			},
			KEMPubKey:             kemPubKey1,
			RemainingLifespanSecs: 3500,
		},
		{
			ID: kem2,
			Algorithm: &keymanager.HpkeAlgorithm{
				Kem:  keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
				Kdf:  keymanager.KdfAlgorithm_KDF_ALGORITHM_HKDF_SHA256,
				Aead: keymanager.AeadAlgorithm_AEAD_ALGORITHM_AES_256_GCM,
			},
			KEMPubKey:             kemPubKey2,
			RemainingLifespanSecs: 7100,
		},
	}

	srv := newTestServer(t,
		&mockKeyProtectionService{enumeratedKeys: mockEnumKeys},
		&mockWorkloadService{},
	)

	req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp api.EnumerateKeysResponse
	if err := protojson.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(resp.KeyInfos) != 2 {
		t.Fatalf("expected 2 key infos, got %d", len(resp.KeyInfos))
	}

	// Verify both keys appear (order-independent).
	found := make(map[string]*api.KeyInfo)
	for i := range resp.KeyInfos {
		ki := resp.KeyInfos[i]
		found[ki.KeyHandle.Handle] = ki
	}

	// Verify key 1.
	info1, ok := found[kem1.String()]
	if !ok {
		t.Fatalf("expected kem1 %s in response", kem1)
	}
	if info1.PubKey.Algorithm.GetParams().GetKemId() != keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256 {
		t.Fatalf("expected algorithm %v, got %v", keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256, info1.PubKey.Algorithm.GetParams().GetKemId())
	}
	if !bytes.Equal(info1.PubKey.PublicKey, kemPubKey1) {
		t.Fatalf("KEM pub key mismatch for kem1")
	}
	if info1.KeyProtectionMechanism != keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM_EMULATED.String() {
		t.Fatalf("expected key protection mechanism %s, got %s", keymanager.KeyProtectionMechanism_KEY_PROTECTION_VM_EMULATED.String(), info1.KeyProtectionMechanism)
	}
	// Approximate check for expiration time
	if info1.ExpirationTime <= float64(time.Now().Unix()) {
		t.Fatalf("expected expiration time in the future, got %f", info1.ExpirationTime)
	}

	// Verify key 2.
	info2, ok := found[kem2.String()]
	if !ok {
		t.Fatalf("expected kem2 %s in response", kem2)
	}
	// Approximate check for expiration time
	if info2.ExpirationTime <= float64(time.Now().Unix()) {
		t.Fatalf("expected expiration time in the future, got %f", info2.ExpirationTime)
	}
}

func TestHandleEnumerateKeysMethodNotAllowed(t *testing.T) {
	srv := newTestServer(t,
		&mockKeyProtectionService{},
		&mockWorkloadService{},
	)

	req := httptest.NewRequest(http.MethodPost, "/v1/keys", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

func TestHandleEnumerateKeysError(t *testing.T) {
	srv := newTestServer(t,
		&mockKeyProtectionService{enumerateErr: fmt.Errorf("enumerate error")},
		&mockWorkloadService{},
	)

	req := httptest.NewRequest(http.MethodGet, "/v1/keys", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d: %s", w.Code, w.Body.String())
	}
}

func TestToHpkeAlgorithm(t *testing.T) {
	tests := []struct {
		input   keymanager.KemAlgorithm
		want    *keymanager.HpkeAlgorithm
		wantErr bool
	}{
		{
			input: keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
			want: &keymanager.HpkeAlgorithm{
				Kem:  keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256,
				Kdf:  keymanager.KdfAlgorithm_KDF_ALGORITHM_HKDF_SHA256,
				Aead: keymanager.AeadAlgorithm_AEAD_ALGORITHM_AES_256_GCM,
			},
			wantErr: false,
		},
		{
			input:   keymanager.KemAlgorithm_KEM_ALGORITHM_UNSPECIFIED,
			want:    nil,
			wantErr: true,
		},
		{
			input:   keymanager.KemAlgorithm(999),
			want:    nil,
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%v", tc.input), func(t *testing.T) {
			got, err := KemToHpkeAlgorithm(tc.input)
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

	var resp api.GetCapabilitiesResponse
	if err := protojson.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(resp.SupportedAlgorithms) != 1 ||
		resp.SupportedAlgorithms[0].Algorithm.GetParams().GetKemId() != keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256 ||
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
		uuid:                  kemUUID,
		pubKey:                kemPubKey,
		bindingPubKey:         bindingPubKey,
		algo:                  expectedAlgo,
		remainingLifespanSecs: 3600,
	}

	srv := newTestServer(t, kps, ws)
	// Populate kemToBindingMap for the claims test.
	srv.kemToBindingMap[kemUUID] = bindingUUID

	t.Run("BindingClaims", func(t *testing.T) {
		respChan := make(chan *ClaimsResult, 1)
		req := &keymanager.GetKeyClaimsRequest{
			KeyHandle: &keymanager.KeyHandle{Handle: kemUUID.String()},
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
			if claims.ExpirationTime <= float64(time.Now().Unix()) {
				t.Errorf("expected expiration time to be in the future, got %v", claims.ExpirationTime)
			}
			if claims.RemainingLifespan.AsDuration() <= 0 { //nolint:staticcheck
				t.Errorf("expected positive remaining lifespan, got %v", claims.RemainingLifespan.AsDuration()) //nolint:staticcheck
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
			if !strings.Contains(res.Err.Error(), "failed to retrieve binding key claims") {
				t.Errorf("expected error to contain 'failed to retrieve binding key claims', got %v", res.Err)
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

func validDestroyBody(handle string) []byte {
	body, _ := protojson.MarshalOptions{EmitUnpopulated: true, UseProtoNames: true}.Marshal(&api.DestroyRequest{
		KeyHandle: &keymanager.KeyHandle{Handle: handle},
	})
	return body
}

func TestHandleDestroy(t *testing.T) {
	validKEMUUID := uuid.New()
	validBindingUUID := uuid.New()

	tests := []struct {
		name                   string
		method                 string
		body                   []byte
		setupMap               bool
		kemDestroyerErr        error
		bindingDestroyerErr    error
		expectedStatus         int
		expectKEMDestroyed     bool
		expectBindingDestroyed bool
		expectMapRemoved       bool
	}{
		{
			name:                   "success",
			method:                 http.MethodPost,
			body:                   validDestroyBody(validKEMUUID.String()),
			setupMap:               true,
			expectedStatus:         http.StatusNoContent,
			expectKEMDestroyed:     true,
			expectBindingDestroyed: true,
			expectMapRemoved:       true,
		},
		{
			name:           "invalid method",
			method:         http.MethodGet,
			body:           nil,
			expectedStatus: http.StatusMethodNotAllowed,
		},
		{
			name:           "bad json",
			method:         http.MethodPost,
			body:           []byte("not json"),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid uuid",
			method:         http.MethodPost,
			body:           validDestroyBody("invalid-uuid"),
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "key not found",
			method:         http.MethodPost,
			body:           validDestroyBody(uuid.New().String()),
			setupMap:       false,
			expectedStatus: http.StatusNotFound,
		},
		{
			name:                   "kps failure",
			method:                 http.MethodPost,
			body:                   validDestroyBody(validKEMUUID.String()),
			setupMap:               true,
			kemDestroyerErr:        fmt.Errorf("KPS error"),
			expectedStatus:         http.StatusInternalServerError,
			expectBindingDestroyed: true,
			expectMapRemoved:       true,
		},
		{
			name:                "binding failure",
			method:              http.MethodPost,
			body:                validDestroyBody(validKEMUUID.String()),
			setupMap:            true,
			bindingDestroyerErr: fmt.Errorf("Binding error"),
			expectedStatus:      http.StatusInternalServerError,
			expectKEMDestroyed:  true,
			expectMapRemoved:    true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			kemDestroyer := &mockKeyProtectionService{destroyErr: tc.kemDestroyerErr}
			bindingDestroyer := &mockWorkloadService{destroyErr: tc.bindingDestroyerErr}

			srv := newTestServer(t, kemDestroyer, bindingDestroyer)

			if tc.setupMap {
				srv.mu.Lock()
				srv.kemToBindingMap[validKEMUUID] = validBindingUUID
				srv.mu.Unlock()
			}

			req := httptest.NewRequest(tc.method, "/v1/keys:destroy", bytes.NewReader(tc.body))
			if tc.body != nil {
				req.Header.Set("Content-Type", "application/json")
			}
			w := httptest.NewRecorder()
			srv.Handler().ServeHTTP(w, req)

			if w.Code != tc.expectedStatus {
				t.Fatalf("expected status %d, got %d: %s", tc.expectedStatus, w.Code, w.Body.String())
			}

			if tc.expectKEMDestroyed {
				if kemDestroyer.destroyedUUID != validKEMUUID {
					t.Fatalf("expected KEM destroy for %s, got %s", validKEMUUID, kemDestroyer.destroyedUUID)
				}
			}

			if tc.expectBindingDestroyed {
				if bindingDestroyer.destroyedUUID != validBindingUUID {
					t.Fatalf("expected Binding destroy for %s, got %s", validBindingUUID, bindingDestroyer.destroyedUUID)
				}
			}

			if tc.setupMap {
				_, ok := srv.LookupBindingUUID(validKEMUUID)
				if tc.expectMapRemoved && ok {
					t.Fatalf("expected KEM UUID to be removed from map")
				} else if !tc.expectMapRemoved && !ok {
					t.Fatalf("expected KEM UUID to persist in map on failure")
				}
			}
		})
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

func decapsRequestBody(kemUUID uuid.UUID, algo keymanager.KemAlgorithm, encKey []byte) string {
	return fmt.Sprintf(
		`{"key_handle":{"handle":"%s"},"ciphertext":{"algorithm":"%s","ciphertext":"%s"}}`,
		kemUUID.String(),
		algo.String(),
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
	expectedAAD := decapsAADContext(kemUUID, keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256)

	ds := &mockKeyProtectionService{sealEnc: sealEnc, sealedCT: sealedCT}
	op := &mockWorkloadService{plaintext: plaintext}
	srv := newDecapsTestServer(t, kemUUID, bindingUUID, ds, op)

	body := decapsRequestBody(kemUUID, keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256, encKey)
	req := httptest.NewRequest(http.MethodPost, "/v1/keys:decap", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp api.DecapsResponse
	if err := protojson.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.SharedSecret.Algorithm != keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256 {
		t.Fatalf("expected shared_secret.algorithm=%d, got %d", keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256, resp.SharedSecret.Algorithm)
	}

	decoded := resp.SharedSecret.Secret
	if string(decoded) != string(plaintext) {
		t.Fatalf("expected plaintext %q, got %q", plaintext, decoded)
	}

	// Verify KeyProtectionService received correct args.
	if ds.receivedKEMUUID != kemUUID {
		t.Fatalf("expected KeyProtectionService to receive KEM UUID %s, got %s", kemUUID, ds.receivedKEMUUID)
	}
	if string(ds.receivedEncKey) != string(encKey) {
		t.Fatalf("expected KeyProtectionService to receive enc key %q, got %q", encKey, ds.receivedEncKey)
	}
	if string(ds.receivedAAD) != string(expectedAAD) {
		t.Fatalf("expected KeyProtectionService to receive AAD %q, got %q", expectedAAD, ds.receivedAAD)
	}

	// Verify WorkloadService received correct args.
	if op.receivedUUID != bindingUUID {
		t.Fatalf("expected WorkloadService to receive binding UUID %s, got %s", bindingUUID, op.receivedUUID)
	}
	if string(op.receivedEnc) != string(sealEnc) {
		t.Fatalf("expected WorkloadService to receive enc %q, got %q", sealEnc, op.receivedEnc)
	}
	if string(op.receivedCT) != string(sealedCT) {
		t.Fatalf("expected WorkloadService to receive CT %q, got %q", sealedCT, op.receivedCT)
	}
	if string(op.receivedAAD) != string(expectedAAD) {
		t.Fatalf("expected WorkloadService to receive AAD %q, got %q", expectedAAD, op.receivedAAD)
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

	body := `{"key_handle":{"handle":"not-a-uuid"},"ciphertext":{"algorithm":"KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256","ciphertext":"AAAA"}}`
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

	body := decapsRequestBody(kemUUID, keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256, []byte("enc-key"))
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

	body := decapsRequestBody(kemUUID, keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256, []byte("enc-key"))
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

	body := decapsRequestBody(kemUUID, keymanager.KemAlgorithm_KEM_ALGORITHM_DHKEM_X25519_HKDF_SHA256, []byte("enc-key"))
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

	body := decapsRequestBody(kemUUID, keymanager.KemAlgorithm(999), []byte("enc-key"))
	req := httptest.NewRequest(http.MethodPost, "/v1/keys:decap", strings.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestProcessClaimsTimeout(t *testing.T) {
	oldTimeout := ClaimsResponseTimeout
	ClaimsResponseTimeout = 10 * time.Millisecond
	defer func() { ClaimsResponseTimeout = oldTimeout }()

	srv := newTestServer(t, &mockKeyProtectionService{}, &mockWorkloadService{})
	// processClaims is already started in newTestServer -> NewServer -> New

	respChan1 := make(chan *ClaimsResult) // Unbuffered
	req1 := &keymanager.GetKeyClaimsRequest{
		KeyHandle: &keymanager.KeyHandle{Handle: uuid.New().String()},
		KeyType:   keymanager.KeyType_KEY_TYPE_VM_PROTECTION_BINDING,
	}

	// 1. Send first request and DO NOT read from it.
	// This should timeout in 10ms.
	srv.claimsChan <- &ClaimsCall{Request: req1, RespChan: respChan1}

	// 2. Send second request and read from it.
	// We need a valid UUID in the map for this to succeed easily.
	kemUUID := uuid.New()
	bindingUUID := uuid.New()
	srv.mu.Lock()
	srv.kemToBindingMap[kemUUID] = bindingUUID
	srv.mu.Unlock()

	respChan2 := make(chan *ClaimsResult, 1)
	req2 := &keymanager.GetKeyClaimsRequest{
		KeyHandle: &keymanager.KeyHandle{Handle: kemUUID.String()},
		KeyType:   keymanager.KeyType_KEY_TYPE_VM_PROTECTION_BINDING,
	}

	// Give it a bit of time for the first one to timeout
	time.Sleep(20 * time.Millisecond)

	srv.claimsChan <- &ClaimsCall{Request: req2, RespChan: respChan2}

	select {
	case res := <-respChan2:
		if res.Err != nil {
			t.Errorf("expected no error for second request, got: %v", res.Err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("timed out waiting for second request response - background worker might be blocked!")
	}
}

func TestGetClaimsFromChannel(t *testing.T) {
	keyHandle := "test-uuid-123"
	expectedReply := &keymanager.KeyClaims{
		Claims: &keymanager.KeyClaims_VmBindingClaims{},
	}

	tests := []struct {
		name           string
		keyType        keymanager.KeyType
		workerBehavior func(call *ClaimsCall)
		ctxTimeout     time.Duration
		wantErr        string
	}{
		{
			name:    "success",
			keyType: keymanager.KeyType_KEY_TYPE_VM_PROTECTION_BINDING,
			workerBehavior: func(call *ClaimsCall) {
				call.RespChan <- &ClaimsResult{Reply: expectedReply}
			},
			ctxTimeout: 5 * time.Second,
			wantErr:    "",
		},
		{
			name:    "worker returns error",
			keyType: keymanager.KeyType_KEY_TYPE_VM_PROTECTION_KEY,
			workerBehavior: func(call *ClaimsCall) {
				call.RespChan <- &ClaimsResult{Err: errors.New("db connection failed")}
			},
			ctxTimeout: 5 * time.Second,
			wantErr:    "worker error: db connection failed",
		},
		{
			name:    "context already cancelled",
			keyType: keymanager.KeyType_KEY_TYPE_VM_PROTECTION_BINDING,
			workerBehavior: func(_ *ClaimsCall) {
				// Worker won't even be reached if ctx is canceled early
			},
			ctxTimeout: -1, // Force immediate cancel
			wantErr:    context.Canceled.Error(),
		},
		{
			name:    "response timeout",
			keyType: keymanager.KeyType_KEY_TYPE_VM_PROTECTION_BINDING,
			workerBehavior: func(_ *ClaimsCall) {
				// Simulate worker hanging by doing nothing
			},
			ctxTimeout: 5 * time.Second,
			wantErr:    "timed out waiting for processClaims",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claimsChan := make(chan *ClaimsCall, 1)
			s := &Server{claimsChan: claimsChan}

			var ctx context.Context
			var cancel context.CancelFunc
			if tt.ctxTimeout < 0 {
				ctx, cancel = context.WithCancel(context.Background())
				cancel() // Pre-cancel
			} else {
				ctx, cancel = context.WithTimeout(context.Background(), tt.ctxTimeout)
				defer cancel()
			}

			go func() {
				select {
				case call := <-claimsChan:
					tt.workerBehavior(call)
				case <-ctx.Done():
					return
				}
			}()

			result, err := s.GetKeyClaims(ctx, keyHandle, tt.keyType)

			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error %q, got %q", tt.wantErr, err.Error())
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result != expectedReply {
				t.Errorf("result mismatch: expected %v, got %v", expectedReply, result)
			}
		})
	}
}
