package cmd

import (
	"bytes"
	"encoding/hex"
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal"
	"github.com/google/go-tpm-tools/internal/test"
	attestpb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/server"
	"google.golang.org/protobuf/proto"
)

func TestAttest(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	ExternalTPM = rwc

	nonce := []byte{0x00, 0x02, 0x04, 0x08}

	commands := []struct {
		name    string
		keyType string
		algo    string
		keyFunc func(io.ReadWriter) (*client.Key, error)
	}{
		{"AttestRSADefaultArg", "default", "rsa", client.AttestationKeyRSA},
		{"AttestECCDefaultArg", "default", "ecc", client.AttestationKeyECC},
	}

	for _, command := range commands {
		t.Run(command.name, func(t *testing.T) {
			outFile := makeTempFile(t, nil)
			defer os.Remove(outFile)

			RootCmd.SetArgs([]string{"attest", command.keyType, "--quiet",
				"--nonce", hex.EncodeToString(nonce), "--algo", command.algo,
				"--output", outFile})
			if err := RootCmd.Execute(); err != nil {
				t.Error(err)
			}

			attestationBytes, err := ioutil.ReadFile(outFile)
			if err != nil {
				t.Fatal(err)
			}

			var attestation attestpb.Attestation
			proto.Unmarshal(attestationBytes, &attestation)

			// Validate AK Pub.
			matchingKeyPub, err := command.keyFunc(rwc)
			if err != nil {
				t.Fatalf("failed to create AK: %v", err)
			}
			pubBytes, err := matchingKeyPub.PublicArea().Encode()
			if err != nil {
				t.Fatalf("failed to encode AK: %v", err)
			}
			if !bytes.Equal(attestation.GetAkPub(), pubBytes) {
				t.Errorf("Attestation AKPub did not match expected AK pub")
			}

			// Validate Quote.
			for _, quote := range attestation.GetQuotes() {
				if err := internal.VerifyQuote(quote, matchingKeyPub.PublicKey(), nonce); err != nil {
					t.Errorf("failed to verify quote: %v", err)
				}
			}

			// Replay Event Log.
			replaySuccess := false
			for _, quote := range attestation.GetQuotes() {
				if _, err := server.ParseAndVerifyEventLog(attestation.GetEventLog(), quote.GetPcrs()); err == nil {
					replaySuccess = true
				}
			}
			if !replaySuccess {
				t.Errorf("failed to replay event log: %v", err)
			}
		})
	}
}
