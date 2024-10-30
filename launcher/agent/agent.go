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
	"encoding/base64"
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
	"github.com/google/go-tpm-tools/verifier/models"
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
	AttestationEvidence([]byte, string) (*evidence, error)
	Refresh(context.Context) error
	Close() error
}

type attestRoot interface {
	// Extend measures the cel content into a measurement register and appends to the CEL.
	Extend(cel.Content) error
	// GetCEL fetches the CEL with events corresponding to the sequence of Extended measurements
	// to this attestation root
	GetCEL() *cel.CEL
	// Attest fetches a technology-specific quote from the root of trust.
	Attest(nonce []byte) (any, error)
}

// AttestAgentOpts contains user generated options when calling the
// VerifyAttestation API
type AttestAgentOpts struct {
	TokenOptions *models.TokenOptions
}

type agent struct {
	measuredRots     []attestRoot
	avRot            attestRoot
	fetchedAK        *client.Key
	client           verifier.Client
	principalFetcher principalIDTokenFetcher
	sigsFetcher      signaturediscovery.Fetcher
	launchSpec       spec.LaunchSpec
	logger           logging.Logger
	sigsCache        *sigsCache
}

// CreateAttestationAgent returns an agent capable of performing remote
// attestation using the machine's (v)TPM to GCE's Attestation Service.
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

	// Add TPM
	logger.Info("Adding TPM PCRs for measurement.")
	var tpmAR = &tpmAttestRoot{
		fetchedAK: ak,
		tpm:       tpm,
	}
	attestAgent.measuredRots = append(attestAgent.measuredRots, tpmAR)

	// check if is a TDX machine
	qp, err := tg.GetQuoteProvider()
	if err != nil {
		return nil, err
	}
	// Use qp.IsSupported to check the TDX RTMR interface is enabled
	if qp.IsSupported() == nil {
		logger.Info("Adding TDX RTMRs for measurement.")
		// try to create tsm client for tdx rtmr
		tsm, err := linuxtsm.MakeClient()
		if err != nil {
			return nil, fmt.Errorf("failed to create TSM for TDX: %v", err)
		}
		var tdxAR = &tdxAttestRoot{
			qp:        qp,
			tsmClient: tsm,
		}
		attestAgent.measuredRots = append(attestAgent.measuredRots, tdxAR)

		logger.Info("Using TDX RTMR as attestation root.")
		attestAgent.avRot = tdxAR
	} else {
		logger.Info("Using TPM PCR as attestation root.")
		attestAgent.avRot = tpmAR
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
// MeasureEvent measures to all Attest Roots.
func (a *agent) MeasureEvent(event cel.Content) error {
	for _, attestRoot := range a.measuredRots {
		if err := attestRoot.Extend(event); err != nil {
			return err
		}
	}
	return nil
}

// Attest fetches the nonce and connection ID from the Attestation Service,
// creates an attestation message, and returns the resultant
// principalIDTokens and Metadata Server-generated ID tokens for the instance.
// When possible, Attest uses the technology-specific attestation root-of-trust
// (TDX RTMR), otherwise falls back to the vTPM.
func (a *agent) Attest(ctx context.Context, opts AttestAgentOpts) ([]byte, error) {
	challenge, err := a.client.CreateChallenge(ctx)
	if err != nil {
		return nil, err
	}

func (a *agent) AttestationEvidence(nonce []byte, principalAud string) (*evidence, error) {
	attEvidence := &evidence{}

	var err error
	attEvidence.PrincipalTokens, err = a.principalFetcher(principalAud)
	if err != nil {
		return nil, fmt.Errorf("failed to get principal tokens: %w", err)
	}

	// attResult can be tdx or tpm or other attest root
	attResult, err := a.avRot.Attest(challenge.Nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to attest: %v", err)
	}

	var cosCel bytes.Buffer
	if err := a.avRot.GetCEL().EncodeCEL(&cosCel); err != nil {
		return nil, err
	}

	req := verifier.VerifyAttestationRequest{
		Challenge:      challenge,
		GcpCredentials: principalTokens,
		TokenOptions:   opts.TokenOptions,
	}

	switch v := attResult.(type) {
	case *pb.Attestation:
		a.logger.Info("attestation through TPM quote")

		v.CanonicalEventLog = cosCel.Bytes()
		attEvidence.TPMAttestation = v
	case *verifier.TDCCELAttestation:
		a.logger.Info("attestation through TDX quote")

		certChain, err := internal.GetCertificateChain(a.fetchedAK.Cert(), http.DefaultClient)
		if err != nil {
			return nil, fmt.Errorf("failed when fetching certificate chain: %w", err)
		}

		v.CanonicalEventLog = cosCel.Bytes()
		v.IntermediateCerts = certChain
		v.AkCert = a.fetchedAK.CertDERBytes()
		attEvidence.TDXAttestation = v
	default:
		return nil, fmt.Errorf("received an unsupported attestation type! %v", v)
	}

	signatures := a.sigsCache.get()
	if len(signatures) > 0 {
		for _, sig := range signatures {
			verifierSig, err := convertOCIToContainerSignature(sig)
			if err != nil {
				a.logger.Error(fmt.Sprintf("error converting container signatures: %v", err))
				continue
			}
			req.ContainerImageSignatures = append(req.ContainerImageSignatures, verifierSig)
		}
		a.logger.Info("Found container image signatures: %v\n", signatures)
	}

	return attEvidence, nil
}

// Attest fetches the nonce and connection ID from the Attestation Service,
// creates an attestation message, and returns the resultant
// principalIDTokens and Metadata Server-generated ID tokens for the instance.
func (a *agent) Attest(ctx context.Context, opts AttestAgentOpts) ([]byte, error) {
	challenge, err := a.client.CreateChallenge(ctx)
	if err != nil {
		return nil, err
	}

	evidence, err := a.AttestationEvidence(challenge.Nonce, challenge.Name)
	if err != nil {
		return nil, err
	}

	req := verifier.VerifyAttestationRequest{
		Challenge:                challenge,
		GcpCredentials:           evidence.PrincipalTokens,
		Attestation:              evidence.TPMAttestation,
		TDCCELAttestation:        evidence.TDXAttestation,
		ContainerImageSignatures: evidence.ContainerSignatures,
		TokenOptions: verifier.TokenOptions{
			CustomAudience: opts.Aud,
			CustomNonce:    opts.Nonces,
			TokenType:      opts.TokenType,
		},
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

func convertOCIToContainerSignature(ociSig oci.Signature) (*verifier.ContainerSignature, error) {
	payload, err := ociSig.Payload()
	if err != nil {
		return nil, fmt.Errorf("failed to get payload from signature [%v]: %v", ociSig, err)
	}
	b64Sig, err := ociSig.Base64Encoded()
	if err != nil {
		return nil, fmt.Errorf("failed to get base64 signature from signature [%v]: %v", ociSig, err)
	}
	sigBytes, err := base64.StdEncoding.DecodeString(b64Sig)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signature for signature [%v]: %v", ociSig, err)
	}
	return &verifier.ContainerSignature{
		Payload:   payload,
		Signature: sigBytes,
	}, nil
}

type tpmAttestRoot struct {
	tpmMu     sync.Mutex
	fetchedAK *client.Key
	tpm       io.ReadWriteCloser
	cosCel    cel.CEL
}

func (t *tpmAttestRoot) GetCEL() *cel.CEL {
	return &t.cosCel
}

func (t *tpmAttestRoot) Extend(c cel.Content) error {
	return t.cosCel.AppendEventPCR(t.tpm, cel.CosEventPCR, defaultCELHashAlgo, c)
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
	cosCel    cel.CEL
}

func (t *tdxAttestRoot) GetCEL() *cel.CEL {
	return &t.cosCel
}

func (t *tdxAttestRoot) Extend(c cel.Content) error {
	return t.cosCel.AppendEventRTMR(t.tsmClient, cel.CosRTMR, c)
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
