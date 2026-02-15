package workload_service

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
)

func validDestroyBody(handle string) []byte {
	body, _ := json.Marshal(DestroyRequest{
		KeyHandle: KeyHandle{Handle: handle},
	})
	return body
}

func TestHandleDestroySuccess(t *testing.T) {
	bindingUUID := uuid.New()
	kemUUID := uuid.New()

	kemDestroyer := &mockKEMKeyDestroyer{}
	bindingDestroyer := &mockBindingKeyDestroyer{}

	srv := NewServer(
		&mockBindingKeyGen{},
		&mockKEMKeyGen{},
		noopDecapSealer(),
		noopOpener(),
		kemDestroyer,
		bindingDestroyer,
	)

	// Pre-populate the map
	srv.mu.Lock()
	srv.kemToBindingMap[kemUUID] = bindingUUID
	srv.mu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/v1/keys:destroy", bytes.NewReader(validDestroyBody(kemUUID.String())))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusNoContent {
		t.Fatalf("expected status 204, got %d: %s", w.Code, w.Body.String())
	}

	// Verify KEM key destroyed
	if kemDestroyer.receivedUUID != kemUUID {
		t.Fatalf("expected KEM destroy for %s, got %s", kemUUID, kemDestroyer.receivedUUID)
	}

	// Verify Binding key destroyed
	if bindingDestroyer.receivedUUID != bindingUUID {
		t.Fatalf("expected Binding destroy for %s, got %s", bindingUUID, bindingDestroyer.receivedUUID)
	}

	// Verify mapping removed
	_, ok := srv.LookupBindingUUID(kemUUID)
	if ok {
		t.Fatal("expected KEM UUID to be removed from map")
	}
}

func TestHandleDestroyInvalidMethod(t *testing.T) {
	srv := NewServer(nil, nil, nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodGet, "/v1/keys:destroy", nil)
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected status 405, got %d", w.Code)
	}
}

func TestHandleDestroyBadJSON(t *testing.T) {
	srv := NewServer(nil, nil, nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/keys:destroy", bytes.NewReader([]byte("not json")))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestHandleDestroyInvalidUUID(t *testing.T) {
	srv := NewServer(nil, nil, nil, nil, nil, nil)
	req := httptest.NewRequest(http.MethodPost, "/v1/keys:destroy", bytes.NewReader(validDestroyBody("invalid-uuid")))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected status 400, got %d", w.Code)
	}
}

func TestHandleDestroyKeyNotFound(t *testing.T) {
	srv := NewServer(nil, nil, noopDecapSealer(), noopOpener(), noopKEMDestroyer(), noopBindingDestroyer())
	// Map is empty
	req := httptest.NewRequest(http.MethodPost, "/v1/keys:destroy", bytes.NewReader(validDestroyBody(uuid.New().String())))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)
	if w.Code != http.StatusNotFound {
		t.Fatalf("expected status 404, got %d", w.Code)
	}
}

func TestHandleDestroyKPSFailure(t *testing.T) {
	bindingUUID := uuid.New()
	kemUUID := uuid.New()

	kemDestroyer := &mockKEMKeyDestroyer{err: fmt.Errorf("KPS error")}
	bindingDestroyer := &mockBindingKeyDestroyer{}

	srv := NewServer(nil, nil, noopDecapSealer(), noopOpener(), kemDestroyer, bindingDestroyer)
	srv.mu.Lock()
	srv.kemToBindingMap[kemUUID] = bindingUUID
	srv.mu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/v1/keys:destroy", bytes.NewReader(validDestroyBody(kemUUID.String())))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
	// Verify mapping NOT removed on error
	_, ok := srv.LookupBindingUUID(kemUUID)
	if !ok {
		t.Fatal("expected mapping to persist on failure")
	}
}

func TestHandleDestroyBindingFailure(t *testing.T) {
	bindingUUID := uuid.New()
	kemUUID := uuid.New()

	kemDestroyer := &mockKEMKeyDestroyer{}
	bindingDestroyer := &mockBindingKeyDestroyer{err: fmt.Errorf("Binding error")}

	srv := NewServer(nil, nil, noopDecapSealer(), noopOpener(), kemDestroyer, bindingDestroyer)
	srv.mu.Lock()
	srv.kemToBindingMap[kemUUID] = bindingUUID
	srv.mu.Unlock()

	req := httptest.NewRequest(http.MethodPost, "/v1/keys:destroy", bytes.NewReader(validDestroyBody(kemUUID.String())))
	w := httptest.NewRecorder()
	srv.Handler().ServeHTTP(w, req)

	if w.Code != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", w.Code)
	}
	// Verify KEM key WAS destroyed (or at least attempted/succeeded since KPS didn't error)
	if kemDestroyer.receivedUUID != kemUUID {
		t.Fatal("expected KEM key destroy to be called")
	}
	// Verify mapping NOT removed on error
	_, ok := srv.LookupBindingUUID(kemUUID)
	if !ok {
		t.Fatal("expected mapping to persist on failure")
	}
}
