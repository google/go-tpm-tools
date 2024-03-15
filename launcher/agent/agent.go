// Package agent coordinates the communication between the TPM and the remote
// attestation service. It handles:
//   - All TPM-related functionality (quotes, logs, certs, etc...)
//   - Fetching the relevant principal ID tokens
//   - Calling VerifyAttestation on the remote service
package agent

import (
	"context"
	"crypto"
	"fmt"
	"io"
	"log"
	"sync"

	"github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/internal/util"
	"github.com/google/go-tpm-tools/launcher/internal/signaturediscovery"
	"github.com/google/go-tpm-tools/launcher/spec"
	"github.com/google/go-tpm-tools/verifier"
	"github.com/google/go-tpm-tools/verifier/oci"
)

var defaultCELHashAlgo = []crypto.Hash{crypto.SHA256, crypto.SHA1}

type principalIDTokenFetcher func(audience string) ([][]byte, error)

// AttestationAgent is an agent that interacts with GCE's Attestation Service
// to Verify an attestation message. It is an interface instead of a concrete
// struct to make testing easier.
type AttestationAgent interface {
	MeasureEvent(cel.Content) error
	Attest(context.Context, AttestAgentOpts) ([]byte, error)
	Refresh(context.Context) error
}

// AttestAgentOpts contains user generated options when calling the
// VerifyAttestation API
type AttestAgentOpts struct {
	Aud       string
	Nonces    []string
	TokenType string
}

type agent struct {
	tpm              io.ReadWriteCloser
	akFetcher        util.TpmKeyFetcher
	client           verifier.Client
	principalFetcher principalIDTokenFetcher
	sigsFetcher      signaturediscovery.Fetcher
	cosCel           cel.CEL
	launchSpec       spec.LaunchSpec
	logger           *log.Logger
	sigsCache        *sigsCache
}

// CreateAttestationAgent returns an agent capable of performing remote
// attestation using the machine's (v)TPM to GCE's Attestation Service.
// - tpm is a handle to the TPM on the instance
// - akFetcher is a func to fetch an attestation key: see go-tpm-tools/client.
// - principalFetcher is a func to fetch GCE principal tokens for a given audience.
// - signaturesFetcher is a func to fetch container image signatures associated with the running workload.
// - logger will log any partial errors returned by VerifyAttestation.
func CreateAttestationAgent(tpm io.ReadWriteCloser, akFetcher util.TpmKeyFetcher, verifierClient verifier.Client, principalFetcher principalIDTokenFetcher, sigsFetcher signaturediscovery.Fetcher, launchSpec spec.LaunchSpec, logger *log.Logger) AttestationAgent {
	return &agent{
		tpm:              tpm,
		client:           verifierClient,
		akFetcher:        akFetcher,
		principalFetcher: principalFetcher,
		sigsFetcher:      sigsFetcher,
		launchSpec:       launchSpec,
		logger:           logger,
		sigsCache:        &sigsCache{},
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
func (a *agent) Attest(ctx context.Context, opts AttestAgentOpts) ([]byte, error) {
	challenge, err := a.client.CreateChallenge(ctx)
	if err != nil {
		return nil, err
	}

	principalTokens, err := a.principalFetcher(challenge.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get principal tokens: %w", err)
	}

	attestation, err := util.FetchAttestation(a.tpm, a.akFetcher, challenge.Nonce)
	if err != nil {
		return nil, err
	}

	req := verifier.VerifyAttestationRequest{
		Challenge:      challenge,
		GcpCredentials: principalTokens,
		Attestation:    attestation,
		TokenOptions: verifier.TokenOptions{
			CustomAudience: opts.Aud,
			CustomNonce:    opts.Nonces,
			TokenType:      opts.TokenType,
		},
	}

	var signatures []oci.Signature
	if a.launchSpec.Experiments.EnableSignedContainerCache {
		signatures = a.sigsCache.get()
	} else {
		signatures = fetchContainerImageSignatures(ctx, a.sigsFetcher, a.launchSpec.SignedImageRepos, a.logger)
	}
	if len(signatures) > 0 {
		req.ContainerImageSignatures = signatures
		a.logger.Printf("Found container image signatures: %v\n", signatures)
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

// Refresh refreshes the internal state of the attestation agent.
// It will reset the container image signatures for now.
func (a *agent) Refresh(ctx context.Context) error {
	if a.launchSpec.Experiments.EnableSignedContainerCache {
		signatures := fetchContainerImageSignatures(ctx, a.sigsFetcher, a.launchSpec.SignedImageRepos, a.logger)
		a.sigsCache.set(signatures)
		a.logger.Printf("Refreshed container image signature cache: %v\n", signatures)
	}
	return nil
}

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

type sigsCache struct {
	mu    sync.RWMutex
	items []oci.Signature
}

func (c *sigsCache) set(sigs []oci.Signature) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.items = make([]oci.Signature, len(sigs))
	copy(c.items, sigs)
}

func (c *sigsCache) get() []oci.Signature {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.items
}
