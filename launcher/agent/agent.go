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
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/go-configfs-tsm/configfs/configfsi"

	"github.com/google/go-configfs-tsm/configfs/linuxtsm"
	tg "github.com/google/go-tdx-guest/client"
	tlabi "github.com/google/go-tdx-guest/client/linuxabi"

	"github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	"github.com/google/go-tpm-tools/launcher/internal/signaturediscovery"
	"github.com/google/go-tpm-tools/launcher/spec"
	pb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/verifier"
	"github.com/google/go-tpm-tools/verifier/oci"
	"github.com/google/go-tpm-tools/verifier/rest"
	"github.com/google/go-tpm-tools/verifier/util"
	"go.uber.org/multierr"
)

var defaultCELHashAlgo = []crypto.Hash{crypto.SHA256, crypto.SHA1}

// attestFunc is used for doAttest indirectly so that unit tests can stub it.
var attestFunc = doAttest

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

type attestRoot interface {
	// Extend measures the cel content into a measurement register and appends to the CEL.
	Extend(cel.Content, *cel.CEL) error
	// Attest fetches a technology-specific quote from the root of trust.
	Attest(nonce []byte) (any, error)
}

// AttestAgentOpts contains user generated options when calling the
// VerifyAttestation API
type AttestAgentOpts struct {
	Aud       string
	Nonces    []string
	TokenType string
}

type agent struct {
	ar               attestRoot
	cosCel           cel.CEL
	fetchedAK        *client.Key
	client           verifier.Client
	principalFetcher principalIDTokenFetcher
	sigsFetcher      signaturediscovery.Fetcher
	launchSpec       spec.LaunchSpec
	logger           logging.Logger
	sigsCache        *sigsCache
}

// CreateAttestationAgent returns an agent capable of performing remote
// attestation using the machine's (v)TPM or TDX quote.
//
// For now, "tpm" and "akFetcher" is still needed even on a TDX quote,
// because we need to extract GCE instance info from the TPM's AK.
// TODO(jiankun): remove "tpm" and "akFetcher" from TDX attestAgent once
// it no longer needs TPM AK for GCE info.
//
// - tpm is a handle to the TPM on the instance
// - akFetcher is a func to fetch an attestation key: see go-tpm-tools/client.
// - principalFetcher is a func to fetch GCE principal tokens for a given audience.
// - signaturesFetcher is a func to fetch container image signatures associated with the running workload.
// - logger will log any partial errors returned by VerifyAttestation.
func CreateAttestationAgent(tpm io.ReadWriteCloser, akFetcher util.TpmKeyFetcher, verifierClient verifier.Client, principalFetcher principalIDTokenFetcher, sigsFetcher signaturediscovery.Fetcher, launchSpec spec.LaunchSpec, logger logging.Logger) (AttestationAgent, error) {
	// Fetched the AK and save it, so the agent doesn't need to create a new key everytime
	ak, err := akFetcher(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to create an Attestation Agent: %w", err)
	}

	attestAgent := &agent{
		client:           verifierClient,
		fetchedAK:        ak,
		principalFetcher: principalFetcher,
		sigsFetcher:      sigsFetcher,
		launchSpec:       launchSpec,
		logger:           logger,
		sigsCache:        &sigsCache{},
	}

	qp, err := tg.GetQuoteProvider()
	if err != nil {
		return nil, fmt.Errorf("GetQuoteProvider should always return nil error, but got %v", err)
	}

	if err := qp.IsSupported(); err != nil {
		// check if the quote provider is backed by TDX
		logger.Info(fmt.Sprintf("Cannot create the TDX quote provider (this is expected on a non-TDX machine): %v", err))
		logger.Info("Using TPM PCRs for measurement")
		// if cannot get a TDX Quote Provider, by default using TPM as the attest root
		attestAgent.ar = &tpmAttestRoot{
			fetchedAK: ak,
			tpm:       tpm,
		}
	} else {
		logger.Info("Using TDX RTMRs for measurement")
		// try to create tsm client for tdx rtmr
		tsm, err := linuxtsm.MakeClient()
		if err != nil {
			return nil, fmt.Errorf("failed to create TSM for TDX: %v", err)
		}

		attestAgent.ar = &tdxAttestRoot{
			qp:        qp,
			tsmClient: tsm,
		}
	}

	return attestAgent, nil
}

// Close cleans up the agent
func (a *agent) Close() error {
	a.fetchedAK.Close()
	return nil
}

// MeasureEvent takes in a cel.Content and appends it to the CEL eventlog
// under the attestation agent.
func (a *agent) MeasureEvent(event cel.Content) error {
	return a.ar.Extend(event, &a.cosCel)
}

// Attest is a thin wrapper of AttestWithRetries with defaultRetryPolicy.
func (a *agent) Attest(ctx context.Context, opts AttestAgentOpts) ([]byte, error) {
	return a.AttestWithRetries(ctx, opts, defaultRetryPolicy)
}

// Attest executes doAttest with retries when 500 errors originate from VerifyAttestation API.
func (a *agent) AttestWithRetries(ctx context.Context, opts AttestAgentOpts, retry func() backoff.BackOff) ([]byte, error) {
	var token []byte
	var err error

	retryErr := backoff.Retry(
		func() error {
			var doErr error
			token, doErr = attestFunc(ctx, a, opts)
			var verifyErr *rest.VerifyAttestationError
			// Retry for VerifyAttestation 500 errors.
			if errors.As(doErr, &verifyErr) && verifyErr.StatusCode() == http.StatusInternalServerError {
				return verifyErr
			}

			// Otherwise, save the error and exit the retry.
			err = doErr
			return nil
		},
		retry(),
	)

	if retryErr != nil || err != nil {
		return nil, multierr.Append(retryErr, err)
	}

	return token, nil
}

// doAttest fetches the nonce and connection ID from the Attestation Service,
// creates an attestation message, and returns the resultant
// principalIDTokens and Metadata Server-generated ID tokens for the instance.
func doAttest(ctx context.Context, a *agent, opts AttestAgentOpts) ([]byte, error) {
	challenge, err := a.client.CreateChallenge(ctx)
	if err != nil {
		return nil, err
	}

	principalTokens, err := a.principalFetcher(challenge.Name)
	if err != nil {
		return nil, fmt.Errorf("failed to get principal tokens: %w", err)
	}

	req := verifier.VerifyAttestationRequest{
		Challenge:      challenge,
		GcpCredentials: principalTokens,
		TokenOptions: verifier.TokenOptions{
			CustomAudience: opts.Aud,
			CustomNonce:    opts.Nonces,
			TokenType:      opts.TokenType,
		},
	}

	attResult, err := a.ar.Attest(challenge.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to attest: %v", err)
	}

	var cosCel bytes.Buffer
	if err := a.cosCel.EncodeCEL(&cosCel); err != nil {
		return nil, err
	}

	switch v := attResult.(type) {
	case *pb.Attestation:
		a.logger.Info("Attest using TPM quote")

		v.CanonicalEventLog = cosCel.Bytes()
		req.Attestation = v
	case *verifier.TDCCELAttestation:
		a.logger.Info("Attest using TDX quote (Public Preview)")

		certChain, err := internal.GetCertificateChain(a.fetchedAK.Cert(), http.DefaultClient)
		if err != nil {
			return nil, fmt.Errorf("failed when fetching certificate chain: %w", err)
		}

		v.CanonicalEventLog = cosCel.Bytes()
		v.IntermediateCerts = certChain
		v.AkCert = a.fetchedAK.CertDERBytes()
		req.TDCCELAttestation = v
	default:
		return nil, fmt.Errorf("received an unsupported attestation type! %v", v)
	}

	signatures := a.sigsCache.get()
	if len(signatures) > 0 {
		req.ContainerImageSignatures = signatures
		a.logger.Info("Found container image signatures: %v\n", "signatures", signatures)
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

type tpmAttestRoot struct {
	tpmMu     sync.Mutex
	fetchedAK *client.Key
	tpm       io.ReadWriteCloser
}

func (t *tpmAttestRoot) Extend(c cel.Content, l *cel.CEL) error {
	return l.AppendEventPCR(t.tpm, cel.CosEventPCR, defaultCELHashAlgo, c)
}

func (t *tpmAttestRoot) Attest(nonce []byte) (any, error) {
	t.tpmMu.Lock()
	defer t.tpmMu.Unlock()

	return t.fetchedAK.Attest(client.AttestOpts{
		Nonce:            nonce,
		CertChainFetcher: http.DefaultClient,
	})
}

type tdxAttestRoot struct {
	tdxMu     sync.Mutex
	qp        *tg.LinuxConfigFsQuoteProvider
	tsmClient configfsi.Client
}

func (t *tdxAttestRoot) Extend(c cel.Content, l *cel.CEL) error {
	return l.AppendEventRTMR(t.tsmClient, cel.CosRTMR, c)
}

func (t *tdxAttestRoot) Attest(nonce []byte) (any, error) {
	t.tdxMu.Lock()
	defer t.tdxMu.Unlock()

	var tdxNonce [tlabi.TdReportDataSize]byte
	copy(tdxNonce[:], nonce)

	rawQuote, err := tg.GetRawQuote(t.qp, tdxNonce)
	if err != nil {
		return nil, err
	}

	ccelData, err := os.ReadFile("/sys/firmware/acpi/tables/data/CCEL")
	if err != nil {
		return nil, err
	}
	ccelTable, err := os.ReadFile("/sys/firmware/acpi/tables/CCEL")
	if err != nil {
		return nil, err
	}

	return &verifier.TDCCELAttestation{
		CcelAcpiTable: ccelTable,
		CcelData:      ccelData,
		TdQuote:       rawQuote,
	}, nil
}

// Refresh refreshes the internal state of the attestation agent.
// It will reset the container image signatures for now.
func (a *agent) Refresh(ctx context.Context) error {
	signatures := fetchContainerImageSignatures(ctx, a.sigsFetcher, a.launchSpec.SignedImageRepos, defaultRetryPolicy, a.logger)
	a.sigsCache.set(signatures)
	a.logger.Info("Refreshed container image signature cache", "signatures", signatures)
	return nil
}

func fetchContainerImageSignatures(ctx context.Context, fetcher signaturediscovery.Fetcher, targetRepos []string, retry func() backoff.BackOff, logger logging.Logger) []oci.Signature {
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
					logger.Error(fmt.Sprintf("Failed to fetch container image signatures from repo: %v", err.Error()), "repo", targetRepo)
				})
			if err != nil {
				logger.Error(fmt.Sprintf("Failed all attempts to refresh container signatures from repo: %v", err.Error()), "repo", targetRepo)
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
