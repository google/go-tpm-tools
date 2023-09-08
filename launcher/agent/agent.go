// Package agent coordinates the communication between the TPM and the remote
// attestation service. It handles:
//   - All TPM-related functionality (quotes, logs, certs, etc...)
//   - Fetching the relevant principal ID tokens
//   - Calling VerifyAttestation on the remote service
package agent

import (
	"bytes"
	"context"
	"crypto"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/launcher/verifier"
	pb "github.com/google/go-tpm-tools/proto/attest"
)

var defaultCELHashAlgo = []crypto.Hash{crypto.SHA256, crypto.SHA1}

type tpmKeyFetcher func(rw io.ReadWriter) (*client.Key, error)
type principalIDTokenFetcher func(audience string) ([][]byte, error)

// AttestationAgent is an agent that interacts with GCE's Attestation Service
// to Verify an attestation message. It is an interface instead of a concrete
// struct to make testing easier.
type AttestationAgent interface {
	MeasureEvent(cel.Content) error
	Attest(context.Context) ([]byte, error)
	WriteCEL(filePath string) error
}

type agent struct {
	tpm              io.ReadWriteCloser
	akFetcher        tpmKeyFetcher
	client           verifier.Client
	principalFetcher principalIDTokenFetcher
	cosCel           cel.CEL
}

// CreateAttestationAgent returns an agent capable of performing remote
// attestation using the machine's (v)TPM to GCE's Attestation Service.
// - tpm is a handle to the TPM on the instance
// - akFetcher is a func to fetch an attestation key: see go-tpm-tools/client.
// - principalFetcher is a func to fetch GCE principal tokens for a given audience.
func CreateAttestationAgent(tpm io.ReadWriteCloser, akFetcher tpmKeyFetcher, verifierClient verifier.Client, principalFetcher principalIDTokenFetcher) AttestationAgent {
	return &agent{
		tpm:              tpm,
		client:           verifierClient,
		akFetcher:        akFetcher,
		principalFetcher: principalFetcher,
	}
}

// MeasureEvent takes in a cel.Content and appends it to the CEL eventlog
// under the attestation agent.
func (a *agent) MeasureEvent(event cel.Content) error {
	return a.cosCel.AppendEvent(a.tpm, cel.CosEventPCR, defaultCELHashAlgo, event)
}

// WriteCEL outputs the CEL to the given file path.
func (a *agent) WriteCEL(filePath string) error {
	f, err := os.Create(filePath)
	if err != nil {
		return fmt.Errorf("failed to create file: %v", err)
	}
	defer f.Close()
	var buf bytes.Buffer
	if err := a.cosCel.EncodeCEL(&buf); err != nil {
		return fmt.Errorf("failed to encode CEL: %v", err)
	}
	f.Write(buf.Bytes())
	return nil
}

// Attest fetches the nonce and connection ID from the Attestation Service,
// creates an attestation message, and returns the resultant
// principalIDTokens and Metadata Server-generated ID tokens for the instance.
func (a *agent) Attest(ctx context.Context) ([]byte, error) {
	challenge, err := a.client.CreateChallenge(ctx)
	if err != nil {
		return nil, err
	}

	principalTokens, err := a.principalFetcher(challenge.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get principal tokens: %w", err)
	}

	attestation, err := a.getAttestation(challenge.Nonce)
	if err != nil {
		return nil, err
	}

	resp, err := a.client.VerifyAttestation(ctx, verifier.VerifyAttestationRequest{
		Challenge:      challenge,
		GcpCredentials: principalTokens,
		Attestation:    attestation,
	})
	if err != nil {
		return nil, err
	}
	return resp.ClaimsToken, nil
}

func (a *agent) getAttestation(nonce []byte) (*pb.Attestation, error) {
	ak, err := a.akFetcher(a.tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to get AK: %v", err)
	}
	defer ak.Close()

	var buf bytes.Buffer
	if err := a.cosCel.EncodeCEL(&buf); err != nil {
		return nil, err
	}

	attestation, err := ak.Attest(client.AttestOpts{Nonce: nonce, CanonicalEventLog: buf.Bytes(), CertChainFetcher: http.DefaultClient})
	if err != nil {
		return nil, fmt.Errorf("failed to attest: %v", err)
	}
	return attestation, nil
}
