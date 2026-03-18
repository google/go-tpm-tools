// Package main provides a manual test client for the WSD daemon.
package main

import (
	"context"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/google/uuid"

	kps "github.com/google/go-tpm-tools/keymanager/key_protection_service"
	algorithms "github.com/google/go-tpm-tools/keymanager/km_common/proto"
	workloadservice "github.com/google/go-tpm-tools/keymanager/workload_service"
	wskcc "github.com/google/go-tpm-tools/keymanager/workload_service/key_custody_core"
)

// realBindingKeyGen wraps the actual WSD KCC FFI.
type realBindingKeyGen struct{}

func (r *realBindingKeyGen) GenerateBindingKeypair(algo *algorithms.HpkeAlgorithm, lifespanSecs uint64) (uuid.UUID, []byte, error) {
	return wskcc.GenerateBindingKeypair(algo, lifespanSecs)
}

func (r *realBindingKeyGen) DestroyBindingKey(bindingUUID uuid.UUID) error {
	return wskcc.DestroyBindingKey(bindingUUID)
}

func (r *realBindingKeyGen) GetBindingKey(id uuid.UUID) ([]byte, *algorithms.HpkeAlgorithm, error) {
	return wskcc.GetBindingKey(id)
}

func (r *realBindingKeyGen) Open(bindingUUID uuid.UUID, enc, ciphertext, aad []byte) ([]byte, error) {
	return wskcc.Open(bindingUUID, enc, ciphertext, aad)
}

func main() {
	log.Println("Initializing WSD server components...")

	socketPath := "/tmp/wsd.sock"

	// Wire up real FFI calls: WSD KCC for binding, KPS KCC (via KPS KOL) for KEM.
	kpsSvc := kps.NewService()
	srv, err := workloadservice.NewServer(
		kpsSvc,
		&realBindingKeyGen{},
		socketPath,
	)
	if err != nil {
		log.Fatalf("Failed to create server: %v", err)
	}

	go func() {
		if err := srv.Serve(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Wait for socket to be created
	ready := false
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(socketPath); err == nil {
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !ready {
		log.Fatal("Timed out waiting for socket")
	}

	log.Println("Server ready. You can now use the following curl command to test:")
	log.Printf("curl --unix-socket %s http://unix/v1/keys:generate_key -H \"Content-Type: application/json\" -d '{\"algorithm\":{\"type\":\"kem\",\"params\":{\"kem_id\":\"DHKEM_X25519_HKDF_SHA256\"}}, \"lifespan\":3600}'", socketPath)
	log.Println("To test unsupported algorithm:")
	log.Printf("curl -v --unix-socket %s http://unix/v1/keys:generate_key -H \"Content-Type: application/json\" -d '{\"algorithm\":{\"type\":\"kem\",\"params\":{\"kem_id\":\"KEM_ALGORITHM_UNSPECIFIED\"}}, \"lifespan\":3600}'", socketPath)

	// Wait for interrupt signal to gracefully shutdown the server
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c

	log.Println("Shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := srv.Shutdown(ctx); err != nil {
		log.Fatalf("Server forced to shutdown: %v", err)
	}

	log.Println("Server exiting")
}
