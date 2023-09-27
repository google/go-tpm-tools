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
	"log"
	"net/http"
	"sync"

	"github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/launcher/internal/oci"
	"github.com/google/go-tpm-tools/launcher/internal/signaturediscovery"
	"github.com/google/go-tpm-tools/launcher/spec"
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
}

type agent struct {
	tpm              io.ReadWriteCloser
	akFetcher        tpmKeyFetcher
	client           verifier.Client
	principalFetcher principalIDTokenFetcher
	sigsFetcher      signaturediscovery.Fetcher
	cosCel           cel.CEL
	launchSpec       spec.LaunchSpec
	logger           *log.Logger
}

// CreateAttestationAgent returns an agent capable of performing remote
// attestation using the machine's (v)TPM to GCE's Attestation Service.
// - tpm is a handle to the TPM on the instance
// - akFetcher is a func to fetch an attestation key: see go-tpm-tools/client.
// - principalFetcher is a func to fetch GCE principal tokens for a given audience.
// - signaturesFetcher is a func to fetch container image signatures associated with the running workload.
// - logger will log any partial errors returned by VerifyAttestation.
func CreateAttestationAgent(tpm io.ReadWriteCloser, akFetcher tpmKeyFetcher, verifierClient verifier.Client, principalFetcher principalIDTokenFetcher, sigsFetcher signaturediscovery.Fetcher, launchSpec spec.LaunchSpec, logger *log.Logger) AttestationAgent {
	return &agent{
		tpm:              tpm,
		client:           verifierClient,
		akFetcher:        akFetcher,
		principalFetcher: principalFetcher,
		sigsFetcher:      sigsFetcher,
		launchSpec:       launchSpec,
		logger:           logger,
	}
}

// MeasureEvent takes in a cel.Content and appends it to the CEL eventlog
// under the attestation agent.
func (a *agent) MeasureEvent(event cel.Content) error {
	return a.cosCel.AppendEvent(a.tpm, cel.CosEventPCR, defaultCELHashAlgo, event)
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

	req := verifier.VerifyAttestationRequest{
		Challenge:      challenge,
		GcpCredentials: principalTokens,
		Attestation:    attestation,
	}

	if a.launchSpec.Experiments.EnableSignedContainerImage {
		signatures := fetchContainerImageSignatures(ctx, a.sigsFetcher, a.launchSpec.SignedImageRepos, a.logger)
		if len(signatures) > 0 {
			req.ContainerImageSignatures = signatures
			a.logger.Printf("Found container image signatures: %v\n", signatures)
		}
	}

	resp, err := a.client.VerifyAttestation(ctx, req)
	if err != nil {
		return nil, err
	}
	if len(resp.PartialErrs) > 0 {
		a.logger.Printf("Partial errors from VerifyAttestation: %v", resp.PartialErrs)
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

// TODO: cache signatures so we don't need to fetch every time.
func fetchContainerImageSignatures(ctx context.Context, fetcher signaturediscovery.Fetcher, targetRepos []string, logger *log.Logger) []oci.Signature {
	signatures := make([][]oci.Signature, len(targetRepos))

	var wg sync.WaitGroup
	for i, repo := range targetRepos {
		wg.Add(1)
		go func(targetRepo string, index int) {
			defer wg.Done()
			sigs, err := fetcher.FetchImageSignatures(ctx, targetRepo)
			if err != nil {
				logger.Printf("Failed to fetch signatures from the target repo [%s]: %v", targetRepo, err)
			} else {
				signatures[index] = sigs
			}
		}(repo, i)
	}
	wg.Wait()

	var foundSigs []oci.Signature
	for _, sigs := range signatures {
		foundSigs = append(foundSigs, sigs...)
	}
	return foundSigs
}
