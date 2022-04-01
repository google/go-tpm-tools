package server

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"

	"github.com/google/go-tpm-tools/internal"
	pb "github.com/google/go-tpm-tools/proto/attest"
	tpmpb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/tpm2"
	"google.golang.org/protobuf/proto"
)

var oidExtensionSubjectAltName = []int{2, 5, 29, 17}

// The hash algorithms we support, in their preferred order of use.
var supportedHashAlgs = []tpm2.Algorithm{
	tpm2.AlgSHA512, tpm2.AlgSHA384, tpm2.AlgSHA256, tpm2.AlgSHA1,
}

const cloudComputeInstanceIdentifierOID = "1.3.6.1.4.1.11129.2.1.21"

// VerifyOpts allows for customizing the functionality of VerifyAttestation.
type VerifyOpts struct {
	// The nonce used when calling client.Attest
	Nonce []byte
	// Trusted public keys that can be used to directly verify the key used for
	// attestation. This option should be used if you already know the AK, as
	// it provides the highest level of assurance.
	TrustedAKs []crypto.PublicKey
	// Allow attestations to be verified using SHA-1. This defaults to false
	// because SHA-1 is a weak hash algorithm with known collision attacks.
	// However, setting this to true may be necessary if the client only
	// supports the legacy event log format. This is the case on older Linux
	// distributions (such as Debian 10).
	AllowSHA1 bool
	// A collection of trusted root CAs that are used to sign AK certificates.
	// The TrustedAKs are used first, followed by TrustRootCerts and
	// IntermediateCerts.
	// Adding a specific TPM manufacturer's root and intermediate CAs means all
	// TPMs signed by that CA will be trusted.
	TrustedRootCerts  []*x509.Certificate
	IntermediateCerts []*x509.Certificate
}

type gceInstanceInfo struct {
	Zone               []byte
	ProjectNumber      int
	ProjectID          []byte
	InstanceID         int
	InstanceName       []byte
	SecurityProperties struct {
		SecurityVersion             int
		IsProduction                bool
		TPMDataAlwaysEncrypted      bool
		SuspendResumeAlwaysDisabled bool
		VMTDAlwaysDisabled          bool
		AlwaysInYawn                bool
	}
}

// VerifyAttestation performs the following checks on an Attestation:
//    - the AK used to generate the attestation is trusted (based on VerifyOpts)
//    - the provided signature is generated by the trusted AK public key
//    - the signature signs the provided quote data
//    - the quote data starts with TPM_GENERATED_VALUE
//    - the quote data is a valid TPMS_QUOTE_INFO
//    - the quote data was taken over the provided PCRs
//    - the provided PCR values match the quote data internal digest
//    - the provided opts.Nonce matches that in the quote data
//    - the provided eventlog matches the provided PCR values
//
// After this, the eventlog is parsed and the corresponding MachineState is
// returned. This design prevents unverified MachineStates from being used.
func VerifyAttestation(attestation *pb.Attestation, opts VerifyOpts) (*pb.MachineState, error) {
	// Verify the AK
	akPubArea, err := tpm2.DecodePublic(attestation.GetAkPub())
	if err != nil {
		return nil, fmt.Errorf("failed to decode AK public area: %w", err)
	}
	akPubKey, err := akPubArea.Key()
	if err != nil {
		return nil, fmt.Errorf("failed to get AK public key: %w", err)
	}

	// Add intermediate certs in the attestation if they exist.
	certs, err := parseCerts(attestation.IntermediateCerts)
	if err != nil {
		return nil, fmt.Errorf("attestation intermediates: %w", err)
	}

	opts.IntermediateCerts = append(opts.IntermediateCerts, certs...)

	machineState, err := validateAK(akPubKey, attestation.GetAkCert(), opts)
	if err != nil {
		return nil, fmt.Errorf("failed to validate AK: %w", err)
	}

	// Verify the signing hash algorithm
	signHashAlg, err := internal.GetSigningHashAlg(akPubArea)
	if err != nil {
		return nil, fmt.Errorf("bad AK public area: %w", err)
	}
	if err = checkHashAlgSupported(signHashAlg, opts); err != nil {
		return nil, fmt.Errorf("in AK public area: %w", err)
	}

	// Attempt to replay the log against our PCRs in order of hash preference
	var lastErr error
	for _, quote := range supportedQuotes(attestation.GetQuotes()) {
		// Verify the Quote
		if err = internal.VerifyQuote(quote, akPubKey, opts.Nonce); err != nil {
			lastErr = fmt.Errorf("failed to verify quote: %w", err)
			continue
		}

		// Parse event logs and replay the events against the provided PCRs
		pcrs := quote.GetPcrs()
		state, err := parsePCClientEventLog(attestation.GetEventLog(), pcrs)
		if err != nil {
			lastErr = fmt.Errorf("failed to validate the PCClient event log: %w", err)
			continue
		}

		celState, err := parseCanonicalEventLog(attestation.GetCanonicalEventLog(), pcrs)
		if err != nil {
			lastErr = fmt.Errorf("failed to validate the Canonical event log: %w", err)
			continue
		}

		proto.Merge(machineState, celState)
		proto.Merge(machineState, state)

		// Verify the PCR hash algorithm. We have this check here (instead of at
		// the start of the loop) so that the user gets a "SHA-1 not supported"
		// error only if allowing SHA-1 support would actually allow the log
		// to be verified. This makes debugging failed verifications easier.
		pcrHashAlg := tpm2.Algorithm(pcrs.GetHash())
		if err = checkHashAlgSupported(pcrHashAlg, opts); err != nil {
			lastErr = fmt.Errorf("when verifying PCRs: %w", err)
			continue
		}

		return celState, nil
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, fmt.Errorf("attestation does not contain a supported quote")
}

// Checks if the provided AK public key can be trusted
func checkAKTrusted(ak crypto.PublicKey, akCertBytes []byte, opts VerifyOpts) (*pb.MachineState, error) {
	checkPub := len(opts.TrustedAKs) > 0
	checkCert := opts.TrustedRootCerts != nil
	if !checkPub && !checkCert {
		return nil, fmt.Errorf("no trust mechanism provided, either use TrustedAKs or TrustedRootCerts")
	}
	if checkPub && checkCert {
		return nil, fmt.Errorf("multiple trust mechanisms provided, only use one of TrustedAKs or TrustedRootCerts")
	}

	// Check against known AKs
	if checkPub {
		for _, trusted := range opts.TrustedAKs {
			if internal.PubKeysEqual(ak, trusted) {
				return &pb.MachineState{}, nil
			}
		}
		return nil, fmt.Errorf("public key is not trusted")
	}

	// Check if the AK Cert chains to a trusted root
	if len(akCertBytes) == 0 {
		return nil, errors.New("no certificate provided in attestation")
	}
	akCert, err := x509.ParseCertificate(akCertBytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	// We manually handle the SAN extension because x509 marks it unhandled if
	// SAN does not parse any of DNSNames, EmailAddresses, IPAddresses, or URIs.
	// https://cs.opensource.google/go/go/+/master:src/crypto/x509/parser.go;l=668-678
	var exts []asn1.ObjectIdentifier
	for _, ext := range akCert.UnhandledCriticalExtensions {
		if ext.Equal(oidExtensionSubjectAltName) {
			continue
		}
		exts = append(exts, ext)
	}
	akCert.UnhandledCriticalExtensions = exts

	x509Opts := x509.VerifyOptions{
		Roots:         makePool(opts.TrustedRootCerts),
		Intermediates: makePool(opts.IntermediateCerts),
		// The default key usage (ExtKeyUsageServerAuth) is not appropriate for
		// an Attestation Key: ExtKeyUsage of
		// - https://oidref.com/2.23.133.8.1
		// - https://oidref.com/2.23.133.8.3
		// https://pkg.go.dev/crypto/x509#VerifyOptions
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsage(x509.ExtKeyUsageAny)},
	}
	if _, err := akCert.Verify(x509Opts); err != nil {
		return nil, fmt.Errorf("failed to verify certificate against trusted roots: %v", err)
	}

	if !internal.PubKeysEqual(ak, akCert.PublicKey) {
		return nil, fmt.Errorf("mismatch between public key and certificate")
	}

	var gceInstanceInfoBytes []byte
	for _, ext := range akCert.Extensions {
		if ext.Id.String() == cloudComputeInstanceIdentifierOID {
			gceInstanceInfoBytes = ext.Value
			break
		}
	}

	// If GCE Instance Info extension is not found.
	if gceInstanceInfoBytes == nil {
		return &pb.MachineState{}, nil
	}

	var parsedInstanceInfo gceInstanceInfo
	if _, err := asn1.Unmarshal(gceInstanceInfoBytes, &parsedInstanceInfo); err != nil {
		return nil, fmt.Errorf("failed to parse GCE Instance Information Extension: %w", err)
	}

	// Check production.
	if !parsedInstanceInfo.SecurityProperties.IsProduction {
		return &pb.MachineState{}, nil
	}

	machineState := &pb.MachineState{
		Platform: &pb.PlatformState{
			InstanceInfo: &pb.GCEInstanceInfo{
				Zone:          string(parsedInstanceInfo.Zone),
				ProjectId:     string(parsedInstanceInfo.ProjectID),
				ProjectNumber: uint64(parsedInstanceInfo.ProjectNumber),
				InstanceName:  string(parsedInstanceInfo.InstanceName),
				InstanceId:    uint64(parsedInstanceInfo.InstanceID),
			},
		},
	}

	return machineState, nil
}

func checkHashAlgSupported(hash tpm2.Algorithm, opts VerifyOpts) error {
	if hash == tpm2.AlgSHA1 && !opts.AllowSHA1 {
		return fmt.Errorf("SHA-1 is not allowed for verification (set VerifyOpts.AllowSHA1 to true to allow)")
	}
	for _, alg := range supportedHashAlgs {
		if hash == alg {
			return nil
		}
	}
	return fmt.Errorf("unsupported hash algorithm: %v", hash)
}

// Retrieve the supported quotes in order of hash preference
func supportedQuotes(quotes []*tpmpb.Quote) []*tpmpb.Quote {
	out := make([]*tpmpb.Quote, 0, len(quotes))
	for _, alg := range supportedHashAlgs {
		for _, quote := range quotes {
			if tpm2.Algorithm(quote.GetPcrs().GetHash()) == alg {
				out = append(out, quote)
				break
			}
		}
	}
	return out
}

func makePool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}
