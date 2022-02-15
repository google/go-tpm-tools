package client

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
	"net/http"

	pb "github.com/google/go-tpm-tools/proto/attest"
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
	// HTTP Client for retrieving Intermediate Certificates.
	certClient *http.Client
}

// Constructs the certificate chain for the key's certificate, using the provided HTTP client.
func (k *Key) getCertificateChain(client *http.Client) ([][]byte, error) {
	var certs [][]byte

	for _, url := range k.cert.IssuingCertificateURL {
		resp, err := http.Get(url)
		if err != nil {
			return nil, fmt.Errorf("failed to retrieve certificate at %v: %v", url, err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return nil, fmt.Errorf("certificate retrieval from %s returned non-OK status: %v", url, resp.StatusCode)
		}
		certBytes, err := ioutil.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body from %s: %v", url, err)
		}

		// Verify that the bytes can be parsed into a certificate.
		_, err = x509.ParseCertificate(certBytes)
		if err != nil {
			return nil, fmt.Errorf("error parsing certificate from %s: %v", url, err)
		}

		certs = append(certs, certBytes)
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
	if opts.certClient != nil {
		attestation.IntermediateCerts, err = k.getCertificateChain(opts.certClient)
		if err != nil {
			return nil, fmt.Errorf("Error creating intermediate cert chain: %v", err)
		}
	}

	return &attestation, nil
}
