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
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"

	tg "github.com/google/go-tdx-guest/client"
	tlabi "github.com/google/go-tdx-guest/client/linuxabi"
	"github.com/google/go-tdx-guest/rtmr"

	gecel "github.com/google/go-eventlog/cel"

	"github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	"github.com/google/go-tpm-tools/launcher/internal/signaturediscovery"
	"github.com/google/go-tpm-tools/launcher/spec"
	teemodels "github.com/google/go-tpm-tools/launcher/teeserver/models"
	pb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/verifier"
	"github.com/google/go-tpm-tools/verifier/models"
	"github.com/google/go-tpm-tools/verifier/oci"
	"github.com/google/go-tpm-tools/verifier/util"
)

const (
	audienceSTS = "https://sts.googleapis.com"
)

type principalIDTokenFetcher func(audience string) ([][]byte, error)

// AttestationAgent is an agent that interacts with GCE's Attestation Service
// to Verify an attestation message. It is an interface instead of a concrete
// struct to make testing easier.
type AttestationAgent interface {
	MeasureEvent(gecel.Content) error
	Attest(context.Context, AttestAgentOpts) ([]byte, error)
	AttestWithClient(ctx context.Context, opts AttestAgentOpts, client verifier.Client) ([]byte, error)
	AttestationEvidence(ctx context.Context, challenge []byte, extraData []byte) (*teemodels.VMAttestation, error)
	Refresh(context.Context) error
	Close() error
}

type attestRoot interface {
	// Extend measures the cel content into a measurement register and appends to the CEL.
	Extend(gecel.Content) error
	// GetCEL fetches the CEL with events corresponding to the sequence of Extended measurements
	// to this attestation root
	GetCEL() gecel.CEL
	// Attest fetches a technology-specific quote from the root of trust.
	Attest(nonce []byte) (any, error)
	// ComputeNonce hashes the challenge and extraData using the algorithm preferred by the attestation root.
	ComputeNonce(challenge []byte, extraData []byte) []byte
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

	pcrSels, err := client.AllocatedPCRs(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to get PCR selections: %v", err)
	}

	var hashAlgos []crypto.Hash
	for _, sel := range pcrSels {
		hashAlgo, err := sel.Hash.Hash()
		if err != nil {
			return nil, fmt.Errorf("failed to get TPM hash algorithm: %v", err)
		}
		hashAlgos = append(hashAlgos, hashAlgo)
	}

	var tpmAR = &tpmAttestRoot{
		fetchedAK: ak,
		tpm:       tpm,
		hashAlgos: hashAlgos,
		cosCel:    gecel.NewPCR(),
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
		var tdxAR = &tdxAttestRoot{
			qp:     qp,
			cosCel: gecel.NewConfComputeMR(),
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
func (a *agent) MeasureEvent(event gecel.Content) error {
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
	if a.client == nil {
		return nil, fmt.Errorf("attest agent does not have initialized verifier client")
	}

	return a.AttestWithClient(ctx, opts, a.client)
}

// AttestWithClient fetches the nonce and connection ID from the Attestation Service via the provided client,
// creates an attestation message, and returns the resultant
// principalIDTokens and Metadata Server-generated ID tokens for the instance.
// When possible, Attest uses the technology-specific attestation root-of-trust
// (TDX RTMR), otherwise falls back to the vTPM.
func (a *agent) AttestWithClient(ctx context.Context, opts AttestAgentOpts, client verifier.Client) ([]byte, error) {
	challenge, err := client.CreateChallenge(ctx)
	if err != nil {
		return nil, err
	}

	tokenOpts := opts.TokenOptions
	if tokenOpts == nil {
		tokenOpts = &models.TokenOptions{TokenType: "OIDC"}
	}

	// The customer is responsible for providing an audience if they provided nonces.
	if tokenOpts.Audience == "" && len(tokenOpts.Nonces) == 0 {
		tokenOpts.Audience = audienceSTS
	}

	principalTokens, err := a.principalFetcher(challenge.Name)
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
		TokenOptions:   tokenOpts,
	}

	switch v := attResult.(type) {
	case *pb.Attestation:
		a.logger.Info("attestation through TPM quote")

		v.CanonicalEventLog = cosCel.Bytes()
		req.Attestation = v
	case *verifier.TDCCELAttestation:
		a.logger.Info("attestation through TDX quote")

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

	resp, err := a.verify(ctx, req, client)
	if err != nil {
		return nil, err
	}

	if len(resp.PartialErrs) > 0 {
		a.logger.Error(fmt.Sprintf("Partial errors from VerifyAttestation: %v", resp.PartialErrs))
	}
	return resp.ClaimsToken, nil
}

// AttestationEvidence returns the attestation evidence (TPM or TDX).
func (a *agent) AttestationEvidence(_ context.Context, challenge []byte, extraData []byte) (*teemodels.VMAttestation, error) {
	if !a.launchSpec.Experiments.EnableAttestationEvidence {
		return nil, fmt.Errorf("attestation evidence is disabled")
	}

	if a.avRot == nil {
		return nil, fmt.Errorf("attestation agent does not have an initialized attestation root")
	}

	// Use nested hashing to separate the prefix, the challenge, and extraData
	// and normalize input length.
	finalNonce := a.avRot.ComputeNonce(challenge, extraData)
	attResult, err := a.avRot.Attest(finalNonce)
	if err != nil {
		return nil, fmt.Errorf("failed to attest: %v", err)
	}

	var cosCel bytes.Buffer
	if err := a.avRot.GetCEL().EncodeCEL(&cosCel); err != nil {
		return nil, err
	}

	attestation := &teemodels.VMAttestation{
		Label:     []byte(teemodels.WorkloadAttestationLabel),
		Challenge: challenge,
		ExtraData: extraData,
		Quote:     &teemodels.VMAttestationQuote{},
	}

	switch v := attResult.(type) {
	case *pb.Attestation:
		attestation.Quote = &teemodels.VMAttestationQuote{
			TPMQuote: convertPBToTPMQuote(v),
		}
	case *verifier.TDCCELAttestation:
		attestation.Quote.TDXCCELQuote = &teemodels.TDXCCELQuote{
			CCELBootEventLog:  v.CcelData,
			CELLaunchEventLog: cosCel.Bytes(),
			TDQuote:           v.TdQuote,
		}
	default:
		return nil, fmt.Errorf("unknown attestation type: %T", v)
	}
	return attestation, nil
}

func (a *agent) verify(ctx context.Context, req verifier.VerifyAttestationRequest, client verifier.Client) (*verifier.VerifyAttestationResponse, error) {
	if a.launchSpec.Experiments.EnableVerifyCS {
		return client.VerifyConfidentialSpace(ctx, req)
	}
	return client.VerifyAttestation(ctx, req)
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
	cosCel    gecel.CEL
	hashAlgos []crypto.Hash
}

func (t *tpmAttestRoot) GetCEL() gecel.CEL {
	return t.cosCel
}

func (t *tpmAttestRoot) Extend(c gecel.Content) error {
	return t.cosCel.AppendEvent(c, t.hashAlgos, cel.CosEventPCR, func(hs crypto.Hash, pcr int, digest []byte) error {
		tpm2Alg, err := tpm2.HashToAlgorithm(hs)
		if err != nil {
			return err
		}
		if err := tpm2.PCRExtend(t.tpm, tpmutil.Handle(pcr), tpm2Alg, digest, ""); err != nil {
			return fmt.Errorf("failed to extend event to PCR%d: %v", pcr, err)
		}
		return nil
	})
}

func (t *tpmAttestRoot) Attest(nonce []byte) (any, error) {
	t.tpmMu.Lock()
	defer t.tpmMu.Unlock()

	return t.fetchedAK.Attest(client.AttestOpts{
		Nonce:            nonce,
		CertChainFetcher: http.DefaultClient,
	})
}

func (t *tpmAttestRoot) ComputeNonce(challenge []byte, extraData []byte) []byte {
	challengeData := challenge
	if extraData != nil {
		extraDataDigest := sha256.Sum256(extraData)
		challengeData = append(challenge, extraDataDigest[:]...)
	}
	challengeDigest := sha256.Sum256(challengeData)
	finalNonce := sha256.Sum256(append([]byte(teemodels.WorkloadAttestationLabel), challengeDigest[:]...))
	return finalNonce[:]
}

type tdxAttestRoot struct {
	tdxMu  sync.Mutex
	qp     *tg.LinuxConfigFsQuoteProvider
	cosCel gecel.CEL
}

func (t *tdxAttestRoot) GetCEL() gecel.CEL {
	return t.cosCel
}

func (t *tdxAttestRoot) Extend(c gecel.Content) error {
	return t.cosCel.AppendEvent(c, []crypto.Hash{crypto.SHA384}, cel.CosCCELMRIndex, func(_ crypto.Hash, mrIndex int, digest []byte) error {
		return rtmr.ExtendDigestSysfs(mrIndex-1, digest) // MR_INDEX - 1 == RTMR_INDEX
	})
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

	ccelData, err := os.ReadFile(internal.CcelEventLogFile)
	if err != nil {
		return nil, err
	}
	ccelTable, err := os.ReadFile(internal.AcpiTableFile)
	if err != nil {
		return nil, err
	}

	return &verifier.TDCCELAttestation{
		CcelAcpiTable: ccelTable,
		CcelData:      ccelData,
		TdQuote:       rawQuote,
	}, nil
}

func (t *tdxAttestRoot) ComputeNonce(challenge []byte, extraData []byte) []byte {
	challengeData := challenge
	if extraData != nil {
		extraDataDigest := sha512.Sum512(extraData)
		challengeData = append(challenge, extraDataDigest[:]...)
	}
	challengeDigest := sha512.Sum512(challengeData)
	finalNonce := sha512.Sum512(append([]byte(teemodels.WorkloadAttestationLabel), challengeDigest[:]...))
	return finalNonce[:]
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

func convertPBToTPMQuote(v *pb.Attestation) *teemodels.TPMQuote {
	var quotes []*teemodels.SignedQuote
	for _, q := range v.GetQuotes() {
		quote := &teemodels.SignedQuote{
			TPMSAttest:    q.GetQuote(),
			TPMTSignature: q.GetRawSig(),
		}
		if pcrs := q.GetPcrs(); pcrs != nil {
			quote.HashAlgorithm = uint32(pcrs.GetHash())
			quote.PCRValues = pcrs.GetPcrs()
		}
		quotes = append(quotes, quote)
	}

	return &teemodels.TPMQuote{
		Quotes:               quotes,
		PCClientBootEventLog: v.GetEventLog(),
		CELLaunchEventLog:    v.GetCanonicalEventLog(),
		Endorsement: &teemodels.TPMAttestationEndorsement{
			AKCertEndorsement: &teemodels.AKCertEndorsement{
				AKCert:      v.GetAkCert(),
				AKCertChain: v.GetIntermediateCerts(),
			},
		},
	}
}
