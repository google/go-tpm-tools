package workload_service

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

// mockBindingKeyGen implements BindingKeyGenerator for testing.
type mockBindingKeyGen struct {
	uuid uuid.UUID
	err  error
}

func (m *mockBindingKeyGen) GenerateBindingKeypair() (uuid.UUID, error) {
	return m.uuid, m.err
}

// mockKEMKeyGen implements KEMKeyGenerator for testing.
type mockKEMKeyGen struct {
	uuid          uuid.UUID
	err           error
	receivedPubKey []byte
}

func (m *mockKEMKeyGen) GenerateKEMKeypair(bindingPubKey []byte) (uuid.UUID, error) {
	m.receivedPubKey = bindingPubKey
	return m.uuid, m.err
}

func TestHandleGenerateBindingKeypair(t *testing.T) {
	expectedUUID := uuid.New()
	srv := NewServer(
		&mockBindingKeyGen{uuid: expectedUUID},
		&mockKEMKeyGen{},
	)

	req := httptest.NewRequest(http.MethodPost, "/keys:generateBindingKeypair", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp GenerateBindingKeypairResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.BindingKeyHandle != expectedUUID.String() {
		t.Fatalf("expected UUID %s, got %s", expectedUUID, resp.BindingKeyHandle)
	}
}

func TestHandleGenerateBindingKeypairMethodNotAllowed(t *testing.T) {
	srv := NewServer(&mockBindingKeyGen{}, &mockKEMKeyGen{})

	req := httptest.NewRequest(http.MethodGet, "/keys:generateBindingKeypair", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

func TestHandleGenerateBindingKeypairError(t *testing.T) {
	srv := NewServer(
		&mockBindingKeyGen{err: fmt.Errorf("FFI error")},
		&mockKEMKeyGen{},
	)

	req := httptest.NewRequest(http.MethodPost, "/keys:generateBindingKeypair", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestHandleGenerateKEMKeypair(t *testing.T) {
	expectedUUID := uuid.New()
	bindingPK := make([]byte, 32)
	for i := range bindingPK {
		bindingPK[i] = byte(i)
	}

	kemGen := &mockKEMKeyGen{uuid: expectedUUID}
	srv := NewServer(&mockBindingKeyGen{}, kemGen)

	body, _ := json.Marshal(GenerateKEMKeypairRequest{
		BindingPublicKey: base64.StdEncoding.EncodeToString(bindingPK),
	})
	req := httptest.NewRequest(http.MethodPost, "/keys:generateKEMKeypair", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp GenerateKEMKeypairResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.KEMKeyHandle != expectedUUID.String() {
		t.Fatalf("expected UUID %s, got %s", expectedUUID, resp.KEMKeyHandle)
	}

	if !bytes.Equal(kemGen.receivedPubKey, bindingPK) {
		t.Fatalf("expected binding public key to be passed through")
	}
}

func TestHandleGenerateKEMKeypairMethodNotAllowed(t *testing.T) {
	srv := NewServer(&mockBindingKeyGen{}, &mockKEMKeyGen{})

	req := httptest.NewRequest(http.MethodGet, "/keys:generateKEMKeypair", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

func TestHandleGenerateKEMKeypairInvalidJSON(t *testing.T) {
	srv := NewServer(&mockBindingKeyGen{}, &mockKEMKeyGen{})

	req := httptest.NewRequest(http.MethodPost, "/keys:generateKEMKeypair", bytes.NewReader([]byte("invalid")))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestHandleGenerateKEMKeypairInvalidBase64(t *testing.T) {
	srv := NewServer(&mockBindingKeyGen{}, &mockKEMKeyGen{})

	body, _ := json.Marshal(GenerateKEMKeypairRequest{
		BindingPublicKey: "not-valid-base64!!!",
	})
	req := httptest.NewRequest(http.MethodPost, "/keys:generateKEMKeypair", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestHandleGenerateKEMKeypairEmptyBindingKey(t *testing.T) {
	srv := NewServer(&mockBindingKeyGen{}, &mockKEMKeyGen{})

	body, _ := json.Marshal(GenerateKEMKeypairRequest{
		BindingPublicKey: base64.StdEncoding.EncodeToString([]byte{}),
	})
	req := httptest.NewRequest(http.MethodPost, "/keys:generateKEMKeypair", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestHandleGenerateKEMKeypairError(t *testing.T) {
	srv := NewServer(
		&mockBindingKeyGen{},
		&mockKEMKeyGen{err: fmt.Errorf("FFI error")},
	)

	body, _ := json.Marshal(GenerateKEMKeypairRequest{
		BindingPublicKey: base64.StdEncoding.EncodeToString(make([]byte, 32)),
	})
	req := httptest.NewRequest(http.MethodPost, "/keys:generateKEMKeypair", bytes.NewReader(body))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}
