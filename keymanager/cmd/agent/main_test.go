package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestRunWSD(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "wsd-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	socketPath := filepath.Join(tmpDir, "wsd.sock")

	ctx, cancel := context.WithCancel(context.Background())

	errChan := make(chan error, 1)
	go func() {
		errChan <- runWSD(ctx, socketPath)
	}()

	// Wait for the socket file to be created to ensure the server has started
	started := false
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(socketPath); err == nil {
			started = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !started {
		t.Fatalf("Socket file %s was not created in time", socketPath)
	}

	// Trigger clean shutdown
	cancel()

	// Wait for the run function to return
	select {
	case err := <-errChan:
		if err != nil {
			t.Errorf("runWSD() returned an unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runWSD() did not shut down cleanly in time")
	}
}

func TestRunWSD_InvalidSocketPath(t *testing.T) {
	ctx := context.Background()

	// Use an impossible path to trigger an error
	socketPath := "/nonexistent/path/wsd.sock"

	err := runWSD(ctx, socketPath)
	if err == nil {
		t.Fatal("Expected runWSD() to return an error for invalid socket path")
	}
}

func TestRunKPS(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	errChan := make(chan error, 1)
	go func() {
		errChan <- runKPS(ctx, 0) // Let OS pick an available port
	}()

	// Give the server a moment to start
	time.Sleep(200 * time.Millisecond)

	// Trigger clean shutdown
	cancel()

	// Wait for the run function to return
	select {
	case err := <-errChan:
		if err != nil {
			t.Errorf("runKPS() returned an unexpected error: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runKPS() did not shut down cleanly in time")
	}
}

func TestRunKPS_InvalidPort(t *testing.T) {
	ctx := context.Background()

	// Use an impossible port
	err := runKPS(ctx, -1)
	if err == nil {
		t.Fatal("Expected runKPS() to return an error for invalid port")
	}
}
