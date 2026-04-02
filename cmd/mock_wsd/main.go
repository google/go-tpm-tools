//go:build linux

// Package main provides a standalone mock_wsd binary to test workload attestation.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"

	clogging "cloud.google.com/go/logging"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/launcher/agent"
	"github.com/google/go-tpm-tools/launcher/spec"
	"github.com/google/go-tpm-tools/launcher/teeserver/models"
	"github.com/google/go-tpm-tools/verifier/util"
)

const (
	mockWsdSocketPath = "/run/workload_attestation.sock"
)

type cmdLogger struct {
	*log.Logger
}

func (l *cmdLogger) Log(severity clogging.Severity, msg string, args ...any) {
	l.Printf("%v: %s %v\n", severity, msg, args)
}

func (l *cmdLogger) Info(msg string, args ...any) {
	l.Printf("INFO: %s %v\n", msg, args)
}

func (l *cmdLogger) Warn(msg string, args ...any) {
	l.Printf("WARN: %s %v\n", msg, args)
}

func (l *cmdLogger) Error(msg string, args ...any) {
	l.Printf("ERROR: %s %v\n", msg, args)
}

func (l *cmdLogger) SerialConsoleFile() *os.File {
	return nil
}

func (l *cmdLogger) Close() {
}

type keyHandle struct {
	Handle string `json:"handle"`
}

type getKeyEndorsementRequest struct {
	Challenge []byte    `json:"challenge"`
	KeyHandle keyHandle `json:"key_handle"`
}

type getKeyEndorsementResponse struct {
	Endorsement keyEndorsement `json:"endorsement"`
}

type keyEndorsement struct {
	VMProtectedKeyEndorsement vmProtectedKeyEndorsement `json:"vm_protected_key_endorsement"`
}

type vmProtectedKeyEndorsement struct {
	BindingKeyAttestation   *keyAttestation `json:"binding_key_attestation,omitempty"`
	ProtectedKeyAttestation *keyAttestation `json:"protected_key_attestation,omitempty"`
}

type keyAttestation struct {
	Attestation *models.VMAttestation `json:"attestation"`
}

func main() {
	if os.Getuid() != 0 {
		log.Println("Warning: mock_wsd usually requires root privileges to create sockets in /run")
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	logger := &cmdLogger{log.New(os.Stdout, "mock_wsd ", log.LstdFlags)}

	// 1. Initialize Attestation Agent for teeserver
	launchSpec := spec.LaunchSpec{}
	launchSpec.Experiments.EnableAttestationEvidence = true

	vTPM, err := os.OpenFile("/dev/tpmrm0", os.O_RDWR, 0)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to open vTPM: %v", err))
	} else {
		defer vTPM.Close()
	}
	var tpmCloser io.ReadWriteCloser
	if vTPM != nil {
		tpmCloser = vTPM
	}

	var akFetcher util.TpmKeyFetcher
	if tpmCloser != nil {
		akFetcher = client.GceAttestationKeyECC
	} else {
		akFetcher = func(_ io.ReadWriter) (*client.Key, error) {
			return nil, fmt.Errorf("no vTPM available")
		}
	}

	attestAgent, err := agent.CreateAttestationAgent(
		tpmCloser, akFetcher, nil, nil, nil, launchSpec, logger,
	)
	if err != nil {
		logger.Error(fmt.Sprintf("failed to create attestation agent: %v", err))
		os.Exit(1)
	}
	defer attestAgent.Close()

	errChan := make(chan error, 1)

	// 2. Start mock_wsd server
	mux := http.NewServeMux()
	// Pass the attestAgent directly to avoid the loopback HTTP call
	mux.HandleFunc("/v1/workload/attestation/key_endorsement", func(w http.ResponseWriter, r *http.Request) {
		handleGetKeyEndorsement(w, r, attestAgent, logger)
	})

	if err := os.RemoveAll(mockWsdSocketPath); err != nil {
		logger.Error(fmt.Sprintf("Failed to remove existing socket %s: %v", mockWsdSocketPath, err))
	}

	listener, err := net.Listen("unix", mockWsdSocketPath)
	if err != nil {
		logger.Error(fmt.Sprintf("Failed to listen on %s: %v", mockWsdSocketPath, err))
		os.Exit(1)
	}
	defer listener.Close()

	if err := os.Chmod(mockWsdSocketPath, 0777); err != nil {
		logger.Warn(fmt.Sprintf("failed to chmod socket %s: %v", mockWsdSocketPath, err))
	}

	logger.Info("Starting mock_wsd server attached to TEE Server", "socket", mockWsdSocketPath)
	go func() {
		errChan <- http.Serve(listener, mux)
	}()

	// 3. Wait for termination
	select {
	case err := <-errChan:
		if err != nil {
			logger.Error(fmt.Sprintf("server error: %v", err))
			os.Exit(1)
		}
	case <-ctx.Done():
		logger.Info("Shutting down mock_wsd server")
	}
}

func handleGetKeyEndorsement(w http.ResponseWriter, r *http.Request, attestAgent agent.AttestationAgent, logger *cmdLogger) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req getKeyEndorsementRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, fmt.Sprintf("Failed to decode request: %v", err), http.StatusBadRequest)
		return
	}

	if len(req.Challenge) == 0 {
		http.Error(w, "challenge is required", http.StatusBadRequest)
		return
	}

	// Call the generic AttestationEvidence function directly from the agent
	attestation, err := attestAgent.AttestationEvidence(r.Context(), req.Challenge, nil)
	if err != nil {
		logger.Error(fmt.Sprintf("Error getting evidence from agent: %v", err))
		http.Error(w, fmt.Sprintf("Internal error: %v", err), http.StatusInternalServerError)
		return
	}

	// Construct the response
	// For the mock, we only include the attestation in BindingKeyAttestation
	resp := getKeyEndorsementResponse{
		Endorsement: keyEndorsement{
			VMProtectedKeyEndorsement: vmProtectedKeyEndorsement{
				BindingKeyAttestation: &keyAttestation{
					Attestation: attestation,
				},
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(resp); err != nil {
		logger.Error(fmt.Sprintf("Error encoding response: %v", err))
	}
}
