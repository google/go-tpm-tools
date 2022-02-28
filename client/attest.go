package client

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	pb "github.com/google/go-tpm-tools/proto/attest"
)

const (
	maxIssuingCertificateURLs = 3
	maxCertChainDepth         = 4
)

// AttestOpts allows for customizing the functionality of Attest.
type AttestOpts struct {
	// A unique, application-specific nonce used to guarantee freshness of the
	// attestation. This must not be empty, and should generally be long enough
	// to make brute force attacks infeasible.
	//
	// For security reasons, applications should not allow for attesting with
	// arbitrary, externally-provided nonces. The nonce should be prefixed or
	// otherwise bound (i.e. via a KDF) to application-specific data. For more
	// information on why this is an issue, see this paper on robust remote
	// attestation protocols:
	// https://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.70.4562&rep=rep1&type=pdf
	Nonce []byte
	// TCG Canonical Event Log to add to the attestation.
	// Currently, we only support PCR replay for PCRs orthogonal to those in the
	// firmware event log, where PCRs 0-9 and 14 are often measured. If the two
	// logs overlap, server-side verification using this library may fail.
	CanonicalEventLog []byte
	// Indicates whether the AK certificate chain should be retrieved for validation.
	// If true, Key.Attest() will construct the certificate chain by making GET requests to
	// the contents of Key.cert.IssuingCertificateURL.
	FetchCertChain bool
}

// Given a certificate, iterates through its IssuingCertificateURLs and returns the certificate
// that signed it. Returns an error if a valid signing certificate is not found.
func fetchIssuingCertificate(cert *x509.Certificate) (*x509.Certificate, error) {
	if cert == nil {
		return nil, fmt.Errorf("provided certificate is nil")
	}
	// For each URL, fetch and parse the certificate, then verify whether it signed cert.
	// If successful, return the parsed certificate. If any step in this process fails, try the next url.
	for _, url := range cert.IssuingCertificateURL {
		resp, err := http.Get(url)
		if err != nil {
			log.Printf("failed to retrieve certificate at %v: %v\n", url, err)
			continue
		}

		if resp.StatusCode != http.StatusOK {
			log.Printf("certificate retrieval from %s returned non-OK status: %v\n", url, resp.StatusCode)
			continue
		}
		certBytes, err := ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			log.Printf("failed to read response body from %s: %v\n", url, err)
			continue
		}

		parsedCert, err := x509.ParseCertificate(certBytes)
		if err != nil {
			log.Printf("failed to parse response from %s into a certificate: %v\n", url, err)
			continue
		}

		// Check if the parsed certificate signed the current one.
		if err = cert.CheckSignatureFrom(parsedCert); err == nil {
			return parsedCert, nil
		}
	}

	return nil, fmt.Errorf("did not find valid signing certificate")
}

// Constructs the certificate chain for the key's certificate, using the provided HTTP client.
func (k *Key) getCertificateChain() ([][]byte, error) {
	if len(k.cert.IssuingCertificateURL) > maxIssuingCertificateURLs {
		return nil, fmt.Errorf("key cert contains too many issuing URLs: got %v, expect no more than %v", len(k.cert.IssuingCertificateURL), maxIssuingCertificateURLs)
	}

	var certs [][]byte
	currentCert := k.cert
	for i := 0; i < maxCertChainDepth; i++ {
		issuingCert, err := fetchIssuingCertificate(currentCert)
		if err != nil {
			return nil, fmt.Errorf("error retrieving certificate chain: %w", err)
		}

		certs = append(certs, issuingCert.Raw)
		// Stop searching if no IssuingCertificateURLs found.
		if len(issuingCert.IssuingCertificateURL) == 0 {
			break
		}

		currentCert = issuingCert
	}

	return certs, nil
}

// Attest generates an Attestation containing the TCG Event Log and a Quote over
// all PCR banks. The provided nonce can be used to guarantee freshness of the
// attestation. This function will return an error if the key is not a
// restricted signing key.
//
// AttestOpts is used for additional configuration of the Attestation process.
// This is primarily used to pass the attestation's nonce:
//
//   attestation, err := key.Attest(client.AttestOpts{Nonce: my_nonce})
func (k *Key) Attest(opts AttestOpts) (*pb.Attestation, error) {
	if len(opts.Nonce) == 0 {
		return nil, fmt.Errorf("provided nonce must not be empty")
	}
	sels, err := implementedPCRs(k.rw)
	if err != nil {
		return nil, err
	}

	attestation := pb.Attestation{}
	if attestation.AkPub, err = k.PublicArea().Encode(); err != nil {
		return nil, fmt.Errorf("failed to encode public area: %w", err)
	}
	attestation.AkCert = k.CertDERBytes()
	for _, sel := range sels {
		quote, err := k.Quote(sel, opts.Nonce)
		if err != nil {
			return nil, err
		}
		attestation.Quotes = append(attestation.Quotes, quote)
	}
	if attestation.EventLog, err = GetEventLog(k.rw); err != nil {
		return nil, fmt.Errorf("failed to retrieve TCG Event Log: %w", err)
	}
	if len(opts.CanonicalEventLog) != 0 {
		attestation.CanonicalEventLog = opts.CanonicalEventLog
	}

	// Construct certficate chain.
	if opts.FetchCertChain && k.cert != nil {
		if attestation.IntermediateCerts, err = k.getCertificateChain(); err != nil {
			return nil, fmt.Errorf("error creating intermediate cert chain: %w", err)
		}
	}

	return &attestation, nil
}
