// package main is the entrypoint for the keymanager workload service daemon.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/google/go-tpm-tools/keymanager/key_protection_service"
	workloadservice "github.com/google/go-tpm-tools/keymanager/workload_service"
)

// TODO: temporary, will move to proto once https://github.com/google/go-tpm-tools/pull/743 is submitted.
const (
	ServiceRoleWSD              = "WSD"
	ServiceRoleKPS              = "KPS"
	ProtectionMechanismEmulated = "KEY_PROTECTION_VM_EMULATED"
	ProtectionMechanismVM       = "KEY_PROTECTION_VM"
)

func main() {
	socketPath := flag.String("socket", "/run/container_launcher/kmaserver.sock", "Path to the unix socket")
	kpsPort := flag.Int("kps-port", 50050, "Port for the KPS gRPC server")
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	mode := os.Getenv("KEY_PROTECTION_MECHANISM")
	if mode == "" {
		mode = ProtectionMechanismEmulated
	}

	role := os.Getenv("SERVICE_ROLE")
	if role == "" {
		role = ServiceRoleWSD
	}

	log.Printf("Starting KeyManager launcher. Mode: %s, Role: %s\n", mode, role)

	var err error
	if mode == ProtectionMechanismVM && role == ServiceRoleKPS {
		err = runKPS(ctx, *kpsPort)
	} else {
		err = runWSD(ctx, *socketPath)
	}

	if err != nil {
		log.Fatalf("Server exited with error: %v", err)
	}
}

func runWSD(ctx context.Context, socketPath string) error {
	socketDir := filepath.Dir(socketPath)
	if err := os.MkdirAll(socketDir, 0755); err != nil {
		return fmt.Errorf("failed to create directory for socket %s: %w", socketDir, err)
	}

	log.Printf("Initializing KeyManager WSD server on unix socket %s", socketPath)
	srv, err := workloadservice.New(ctx, socketPath)
	if err != nil {
		return fmt.Errorf("failed to create WSD server: %w", err)
	}

	errChan := make(chan error, 1)
	go func() {
		if err := srv.Serve(); err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("unix socket server failed: %w", err)
		}
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		log.Println("Shutting down WSD server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("error during unix socket shutdown: %w", err)
		}
		return nil
	}
}

func runKPS(ctx context.Context, port int) error {
	log.Printf("Initializing Key Protection Service on TCP port %d", port)
	srv, err := keyprotectionservice.NewServer(port)
	if err != nil {
		return fmt.Errorf("failed to create KPS server: %w", err)
	}

	errChan := make(chan error, 1)
	go func() {
		if err := srv.Serve(); err != nil {
			errChan <- fmt.Errorf("gRPC server failed: %w", err)
		}
	}()

	select {
	case err := <-errChan:
		return err
	case <-ctx.Done():
		log.Println("Shutting down KPS server...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("error during gRPC shutdown: %w", err)
		}
		return nil
	}
}
