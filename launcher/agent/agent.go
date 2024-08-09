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
	"log/slog"
	"net/http"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/launcher/internal/signaturediscovery"
	"github.com/google/go-tpm-tools/launcher/spec"
	pb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/verifier"
	"github.com/google/go-tpm-tools/verifier/oci"
	"github.com/google/go-tpm-tools/verifier/util"
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
	Close() error
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
	tpmMu            sync.Mutex
	fetchedAK        *client.Key
	client           verifier.Client
	principalFetcher principalIDTokenFetcher
	sigsFetcher      signaturediscovery.Fetcher
	cosCel           cel.CEL
	launchSpec       spec.LaunchSpec
	logger           *slog.Logger
	sigsCache        *sigsCache
}

// CreateAttestationAgent returns an agent capable of performing remote
// attestation using the machine's (v)TPM to GCE's Attestation Service.
// - tpm is a handle to the TPM on the instance
// - akFetcher is a func to fetch an attestation key: see go-tpm-tools/client.
// - principalFetcher is a func to fetch GCE principal tokens for a given audience.
// - signaturesFetcher is a func to fetch container image signatures associated with the running workload.
// - logger will log any partial errors returned by VerifyAttestation.
func CreateAttestationAgent(tpm io.ReadWriteCloser, akFetcher util.TpmKeyFetcher, verifierClient verifier.Client, principalFetcher principalIDTokenFetcher, sigsFetcher signaturediscovery.Fetcher, launchSpec spec.LaunchSpec, logger *slog.Logger) (AttestationAgent, error) {
	// Fetched the AK and save it, so the agent doesn't need to create a new key everytime
	ak, err := akFetcher(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to create an Attestation Agent: %w", err)
	}
	return &agent{
		tpm:              tpm,
		client:           verifierClient,
		fetchedAK:        ak,
		principalFetcher: principalFetcher,
		sigsFetcher:      sigsFetcher,
		launchSpec:       launchSpec,
		logger:           logger,
		sigsCache:        &sigsCache{},
	}, nil
}

// Close cleans up the agent
func (a *agent) Close() error {
	a.fetchedAK.Close()
	return nil
}

// MeasureEvent takes in a cel.Content and appends it to the CEL eventlog
// under the attestation agent.
func (a *agent) MeasureEvent(event cel.Content) error {
	a.tpmMu.Lock()
	defer a.tpmMu.Unlock()
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

	var buf bytes.Buffer
	if err := a.cosCel.EncodeCEL(&buf); err != nil {
		return nil, err
	}

	attestation, err := a.attest(challenge.Nonce, buf.Bytes())
	if err != nil {
		return nil, fmt.Errorf("failed to attest: %v", err)
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

	signatures := a.sigsCache.get()
	if len(signatures) > 0 {
		req.ContainerImageSignatures = signatures
		a.logger.Info(fmt.Sprintf("Found container image signatures: %v\n", signatures))
	}

	resp, err := a.client.VerifyAttestation(ctx, req)
	if err != nil {
		return nil, err
	}
	if len(resp.PartialErrs) > 0 {
		a.logger.Error(fmt.Sprintf("Partial errors from VerifyAttestation: %v", resp.PartialErrs))
	}
	return resp.ClaimsToken, nil
}

func (a *agent) attest(nonce []byte, cel []byte) (*pb.Attestation, error) {
	a.tpmMu.Lock()
	defer a.tpmMu.Unlock()
	return a.fetchedAK.Attest(client.AttestOpts{Nonce: nonce, CanonicalEventLog: cel, CertChainFetcher: http.DefaultClient})
}

// Refresh refreshes the internal state of the attestation agent.
// It will reset the container image signatures for now.
func (a *agent) Refresh(ctx context.Context) error {
	signatures := fetchContainerImageSignatures(ctx, a.sigsFetcher, a.launchSpec.SignedImageRepos, defaultRetryPolicy, a.logger)
	a.sigsCache.set(signatures)
	a.logger.Printf("Refreshed container image signature cache: %v\n", signatures)
	return nil
}

func fetchContainerImageSignatures(ctx context.Context, fetcher signaturediscovery.Fetcher, targetRepos []string, retry func() backoff.BackOff, logger *log.Logger) []oci.Signature {
	signatures := make([][]oci.Signature, len(targetRepos))

	var wg sync.WaitGroup
	for i, repo := range targetRepos {
		wg.Add(1)
		go func(targetRepo string, index int) {
			defer wg.Done()

			// backoff independently per repo
			var sigs []oci.Signature
			err := backoff.RetryNotify(
				func() error {
					s, err := fetcher.FetchImageSignatures(ctx, targetRepo)
					sigs = s
					return err
				},
				retry(),
				func(err error, _ time.Duration) {
					logger.Printf("Failed to fetch container image signatures from repo %q: %v", targetRepo, err)
				})
			if err != nil {
				logger.Printf("Failed all attempts to refresh container signatures from repo %q: %v", targetRepo, err)
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

func defaultRetryPolicy() backoff.BackOff {
	b := backoff.NewConstantBackOff(time.Millisecond * 300)
	return backoff.WithMaxRetries(b, 3)
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
