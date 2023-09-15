package client

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sgtest "github.com/google/go-sev-guest/testing"
	testclient "github.com/google/go-sev-guest/testing/client"
	tgtest "github.com/google/go-tdx-guest/testing"
	tgtestclient "github.com/google/go-tdx-guest/testing/client"
	tgtestdata "github.com/google/go-tdx-guest/testing/testdata"
	"github.com/google/go-tpm-tools/internal/test"
	pb "github.com/google/go-tpm-tools/proto/attest"
)

var localClient = http.DefaultClient

// Returns an x509 Certificate with the provided issuingURL and signed with the provided parent certificate and key.
// If parentCert and parentKey are nil, the certificate will be self-signed.
func getTestCert(t *testing.T, issuingURL []string, parentCert *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()

	certKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
		IssuingCertificateURL: issuingURL,
	}

	if parentCert == nil && parentKey == nil {
		parentCert = template
		parentKey = certKey
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, parentCert, certKey.Public(), parentKey)
	if err != nil {
		t.Fatalf("Unable to create test certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("Unable to parse test certificate: %v", err)
	}

	return cert, certKey
}

func TestFetchIssuingCertificateSucceeds(t *testing.T) {
	testCA, caKey := getTestCert(t, nil, nil, nil)

	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write(testCA.Raw)
	}))
	defer ts.Close()

	leafCert, _ := getTestCert(t, []string{"invalid.URL", ts.URL}, testCA, caKey)

	cert, err := fetchIssuingCertificate(localClient, leafCert)
	if err != nil || cert == nil {
		t.Errorf("fetchIssuingCertificate() did not find valid intermediate cert: %v", err)
	}
}

func TestFetchIssuingCertificateReturnsErrorIfMalformedCertificateFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("these are some random bytes"))
	}))
	defer ts.Close()

	testCA, caKey := getTestCert(t, nil, nil, nil)
	leafCert, _ := getTestCert(t, []string{ts.URL}, testCA, caKey)

	_, err := fetchIssuingCertificate(localClient, leafCert)
	if err == nil {
		t.Fatal("expected fetchIssuingCertificate to fail with malformed cert")
	}
}

func TestGetCertificateChainSucceeds(t *testing.T) {
	// Create CA and corresponding server.
	testCA, caKey := getTestCert(t, nil, nil, nil)

	caServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write(testCA.Raw)
	}))

	defer caServer.Close()

	// Create intermediate cert and corresponding server.
	intermediateCert, intermediateKey := getTestCert(t, []string{caServer.URL}, testCA, caKey)

	intermediateServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write(intermediateCert.Raw)
	}))
	defer intermediateServer.Close()

	// Create leaf cert.
	leafCert, _ := getTestCert(t, []string{intermediateServer.URL}, intermediateCert, intermediateKey)

	key := &Key{cert: leafCert}

	certChain, err := key.getCertificateChain(localClient)
	if err != nil {
		t.Fatal(err)
	}
	if len(certChain) != 2 {
		t.Fatalf("getCertificateChain did not return the expected number of certificates: got %v, want 2", len(certChain))
	}
}

func TestKeyAttestSucceedsWithCertChainRetrieval(t *testing.T) {
	testCA, caKey := getTestCert(t, nil, nil, nil)

	caServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write(testCA.Raw)
	}))

	defer caServer.Close()

	leafCert, _ := getTestCert(t, []string{caServer.URL}, testCA, caKey)

	rwc := test.GetTPM(t)
	defer CheckedClose(t, rwc)

	ak, err := AttestationKeyRSA(rwc)
	if err != nil {
		t.Fatalf("Failed to generate test AK: %v", err)
	}

	ak.cert = leafCert

	attestation, err := ak.Attest(AttestOpts{Nonce: []byte("some nonce"), CertChainFetcher: localClient})
	if err != nil {
		t.Fatalf("Attest returned with error: %v", err)
	}

	// Expect one cert retrieved.
	if len(attestation.IntermediateCerts) != 1 {
		t.Fatalf("Got %v intermediate certs, want 1.", len(attestation.IntermediateCerts))
	}

	if !bytes.Equal(attestation.IntermediateCerts[0], testCA.Raw) {
		t.Errorf("Attestation does not contain the expected intermediate cert: got %v, want %v", attestation.IntermediateCerts[0], testCA.Raw)
	}
}

func TestKeyAttestGetCertificateChainConditions(t *testing.T) {
	rwc := test.GetTPM(t)
	defer CheckedClose(t, rwc)

	ak, err := AttestationKeyRSA(rwc)
	if err != nil {
		t.Fatalf("Failed to generate test AK: %v", err)
	}

	akCert, _ := getTestCert(t, nil, nil, nil)

	testcases := []struct {
		name                 string
		fetchCertChainClient *http.Client
		cert                 *x509.Certificate
	}{
		{
			name:                 "CertChainFetcher is nil",
			fetchCertChainClient: nil,
			cert:                 nil,
		},
		{
			name:                 "CertChainFetcher is present, key.cert is nil",
			fetchCertChainClient: localClient,
			cert:                 nil,
		},
		{
			name:                 "CertChainFetcher is present, key.cert has nil IssuingCertificateURL",
			fetchCertChainClient: localClient,
			cert:                 akCert,
		},
	}

	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			ak.cert = tc.cert

			att, err := ak.Attest(AttestOpts{Nonce: []byte("some nonce"), CertChainFetcher: tc.fetchCertChainClient})
			if err != nil {
				t.Fatalf("Attest returned error: %v", err)
			}

			if len(att.IntermediateCerts) != 0 {
				t.Errorf("Attest() returned with intermediate certs, expected no certs retrieved.")
			}
		})
	}
}

func TestSevSnpDevice(t *testing.T) {
	rwc := test.GetTPM(t)
	defer CheckedClose(t, rwc)

	ak, err := AttestationKeyRSA(rwc)
	if err != nil {
		t.Fatalf("Failed to generate test AK: %v", err)
	}

	someNonce := []byte("some nonce")
	var someNonce64 [64]byte
	copy(someNonce64[:], someNonce)
	var nonce64 [64]byte
	copy(nonce64[:], []byte("noncey business"))
	sevTestDevice, _, _, _ := testclient.GetSevGuest([]sgtest.TestCase{
		{
			Input:  someNonce64,
			Output: sgtest.TestRawReport(someNonce64),
		},
		{
			Input:  nonce64,
			Output: sgtest.TestRawReport(nonce64),
		},
	}, &sgtest.DeviceOptions{Now: time.Now()}, t)
	defer sevTestDevice.Close()

	testcases := []struct {
		name           string
		opts           AttestOpts
		wantReportData [64]byte
		wantErr        string
	}{
		{
			name: "Happy case no nonce",
			opts: AttestOpts{
				Nonce:            someNonce,
				CertChainFetcher: localClient,
				TEEDevice:        &SevSnpDevice{sevTestDevice},
			},
			wantReportData: someNonce64,
		},
		{
			name: "Happy case with nonce",
			opts: AttestOpts{
				Nonce:            someNonce,
				CertChainFetcher: localClient,
				TEEDevice:        &SevSnpDevice{sevTestDevice},
				TEENonce:         nonce64[:],
			},
			wantReportData: nonce64,
		},
		{
			name: "TEE nonce without TEE",
			opts: AttestOpts{
				Nonce:            someNonce,
				CertChainFetcher: localClient,
				TEENonce:         nonce64[:],
			},
			wantErr: "got non-nil TEENonce when TEEDevice is nil",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			att, err := ak.Attest(tc.opts)
			if (err == nil && tc.wantErr != "") || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("Attest(%v) = %v, want %q", tc.opts, err, tc.wantErr)
			}
			// Successful attestation should include a SEV-SNP attestation.
			if err == nil {
				snp, ok := att.GetTeeAttestation().(*pb.Attestation_SevSnpAttestation)
				if !ok {
					t.Fatalf("Attestation missing SEV-SNP attestation: %v", att.GetTeeAttestation())
				}
				report := snp.SevSnpAttestation.Report
				if !bytes.Equal(report.GetReportData(), tc.wantReportData[:]) {
					t.Fatalf("SEV-SNP nonces differ. Got %v, want %v", report.GetReportData(), tc.wantReportData)
				}
			}
		})
	}
}

func TestTdxDevice(t *testing.T) {
	rwc := test.GetTPM(t)
	defer CheckedClose(t, rwc)

	ak, err := AttestationKeyRSA(rwc)
	if err != nil {
		t.Fatalf("Failed to generate test AK: %v", err)
	}

	someNonce := []byte("some nonce")
	var someNonce64 [64]byte
	copy(someNonce64[:], someNonce)
	var nonce64 [64]byte
	copy(nonce64[:], []byte("noncey business"))
	tdxTestDevice := tgtestclient.GetTdxGuest([]tgtest.TestCase{
		{
			Input: someNonce64,
			Quote: tgtestdata.RawQuote,
		},
		{
			Input: nonce64,
			Quote: tgtestdata.RawQuote,
		},
	}, t)
	defer tdxTestDevice.Close()

	testcases := []struct {
		name           string
		opts           AttestOpts
		wantReportData [64]byte
		wantErr        string
	}{
		{
			name: "Happy case no nonce",
			opts: AttestOpts{
				Nonce:     someNonce,
				TEEDevice: &TdxDevice{tdxTestDevice},
			},
			wantReportData: someNonce64,
		},
		{
			name: "Happy case with nonce",
			opts: AttestOpts{
				Nonce:     someNonce,
				TEEDevice: &TdxDevice{tdxTestDevice},
				TEENonce:  nonce64[:],
			},
			wantReportData: nonce64,
		},
		{
			name: "TEE nonce without TEE",
			opts: AttestOpts{
				Nonce:    someNonce,
				TEENonce: nonce64[:],
			},
			wantErr: "got non-nil TEENonce when TEEDevice is nil",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			att, err := ak.Attest(tc.opts)
			if (err == nil && tc.wantErr != "") || (err != nil && !strings.Contains(err.Error(), tc.wantErr)) {
				t.Fatalf("Attest(%v) = %v, want %q", tc.opts, err, tc.wantErr)
			}
			// Successful attestation should include a TDX attestation.
			if err == nil {
				_, ok := att.GetTeeAttestation().(*pb.Attestation_TdxAttestation)
				if !ok {
					t.Fatalf("Attestation missing TDX attestation: %v", att.GetTeeAttestation())
				}
			}
		})
	}
}
