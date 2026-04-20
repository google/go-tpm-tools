package keyprotectionservice

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestServerRunAndShutdown(t *testing.T) {
	// Let the OS pick an available port
	srv, err := newServerWithKPS(0, NewService())
	if err != nil {
		t.Fatalf("Failed to create KPS server: %v", err)
	}

	// Verify the listener was created
	addr := srv.listener.Addr().(*net.TCPAddr)
	if addr.Port == 0 {
		t.Fatalf("Expected a non-zero port assigned, got %d", addr.Port)
	}

	errChan := make(chan error, 1)
	go func() {
		// Serve() returns nil upon GracefulStop()
		errChan <- srv.Serve()
	}()

	// Allow the server some time to start up
	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		t.Fatalf("Server shutdown failed: %v", err)
	}

	// Ensure Serve() returned without unexpected errors
	select {
	case err := <-errChan:
		if err != nil {
			t.Fatalf("Serve() returned unexpected error: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("Serve() did not return in time after shutdown")
	}
}

func TestServerInvalidPort(t *testing.T) {
	// Try to start on a system/reserved port that we likely cannot bind to, or invalid port string
	// Passing an invalid port like -1 causes net.Listen to fail
	_, err := NewServer(-1)
	if err == nil {
		t.Fatal("Expected NewServer() to return an error for invalid port -1")
	}
}
