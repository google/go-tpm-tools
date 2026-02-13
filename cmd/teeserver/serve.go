//go:build linux

package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"

	clogging "cloud.google.com/go/logging"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/launcher/agent"
	"github.com/google/go-tpm-tools/launcher/spec"
	"github.com/google/go-tpm-tools/launcher/teeserver"
	"github.com/google/go-tpm-tools/verifier/util"
	"github.com/spf13/cobra"
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

func init() {
	rootCmd.AddCommand(serveCmd)
}

var serveCmd = &cobra.Command{
	Use:   "serve",
	Short: "Start the TEE server",
	RunE: func(_ *cobra.Command, _ []string) error {
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
		defer stop()

		logger := &cmdLogger{log.New(os.Stdout, "teeserver ", log.LstdFlags)}

		launchSpec := spec.LaunchSpec{}
		launchSpec.Experiments.EnableAttestationEvidence = false

		vTPM, err := os.OpenFile("/dev/tpmrm0", os.O_RDWR, 0)
		if err != nil {
			logger.Error(fmt.Sprintf("Failed to open vTPM (but proceeding as TDX might not need it if TDX RTMR is used): %v", err))
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
			tpmCloser,
			akFetcher, // AK fetcher
			nil,       // Mock Verifier client
			nil,       // Mock principal fetcher
			nil,       // Mock sigs fetcher
			launchSpec,
			logger,
		)
		if err != nil {
			return fmt.Errorf("failed to create attestation agent: %w", err)
		}
		defer attestAgent.Close()

		clients := teeserver.AttestClients{
			GCA: nil,
			ITA: nil,
		}

		server, err := teeserver.New(ctx, socketPath, attestAgent, logger, launchSpec, clients)
		if err != nil {
			return fmt.Errorf("failed to create tee server: %w", err)
		}

		logger.Info("Starting TEE Server", "socket", socketPath)

		errChan := make(chan error, 1)
		go func() {
			errChan <- server.Serve()
		}()

		select {
		case err := <-errChan:
			if err != nil {
				return fmt.Errorf("server error: %w", err)
			}
		case <-ctx.Done():
			logger.Info("Shutting down TEE Server")
			if err := server.Shutdown(context.Background()); err != nil {
				// The underlying netListener is closed by Shutdown(), which causes the server
				// to return a "use of closed network connection" error. This is expected.
				if !strings.Contains(err.Error(), "use of closed network connection") {
					return fmt.Errorf("failed to shutdown server: %w", err)
				}
			}
		}

		return nil
	},
}
