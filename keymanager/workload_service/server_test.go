package workload_service

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)



func TestHandleGenerateKeysSuccess(t *testing.T) {
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

	req := httptest.NewRequest(http.MethodPost, "/keys:generate", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected status 200, got %d: %s", w.Code, w.Body.String())
	}

	var resp GenerateKeysResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if resp.KEMKeyHandle != kemUUID.String() {
		t.Fatalf("expected KEM UUID %s, got %s", kemUUID, resp.KEMKeyHandle)
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

	// Verify the KEM → Binding mapping was stored.
	mappedBinding, ok := srv.LookupBindingUUID(kemUUID)
	if !ok {
		t.Fatal("expected KEM UUID to be in kemToBindingMap")
	}
	if mappedBinding != bindingUUID {
		t.Fatalf("expected mapped binding UUID %s, got %s", bindingUUID, mappedBinding)
	}
}

func TestHandleGenerateKeysMethodNotAllowed(t *testing.T) {
	srv := NewServer(
		&mockBindingKeyGen{pubKey: make([]byte, 32)},
		&mockKEMKeyGen{pubKey: make([]byte, 32)},
	)

	req := httptest.NewRequest(http.MethodGet, "/keys:generate", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

func TestHandleGenerateKeysBindingGenError(t *testing.T) {
	srv := NewServer(
		&mockBindingKeyGen{err: fmt.Errorf("binding FFI error")},
		&mockKEMKeyGen{pubKey: make([]byte, 32)},
	)

	req := httptest.NewRequest(http.MethodPost, "/keys:generate", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestHandleGenerateKeysKEMGenError(t *testing.T) {
	srv := NewServer(
		&mockBindingKeyGen{uuid: uuid.New(), pubKey: make([]byte, 32)},
		&mockKEMKeyGen{err: fmt.Errorf("KEM FFI error")},
	)

	req := httptest.NewRequest(http.MethodPost, "/keys:generate", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
}

func TestHandleGenerateKeysMapUniqueness(t *testing.T) {
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

	req := httptest.NewRequest(http.MethodPost, "/keys:generate", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("call 1: expected status 200, got %d: %s", w.Code, w.Body.String())
	}
	callCount++

	// Second call.
	bindingGen.uuid = bindingUUID2
	kemGen.uuid = kemUUID2

	req = httptest.NewRequest(http.MethodPost, "/keys:generate", nil)
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
