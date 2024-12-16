package client

import (
	"bytes"
	"crypto/x509"
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

func TestKeyAttestSucceedsWithCertChainRetrieval(t *testing.T) {
	testCA, caKey := test.GetTestCert(t, nil, nil, nil)

	caServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write(testCA.Raw)
	}))

	defer caServer.Close()

	leafCert, _ := test.GetTestCert(t, []string{caServer.URL}, testCA, caKey)

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

	akCert, _ := test.GetTestCert(t, nil, nil, nil)

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

func TestSevSnpQuoteProvider(t *testing.T) {
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
	sevTestQp, _, _, _ := testclient.GetSevQuoteProvider([]sgtest.TestCase{
		{
			Input:  someNonce64,
			Output: sgtest.TestRawReport(someNonce64),
		},
		{
			Input:  nonce64,
			Output: sgtest.TestRawReport(nonce64),
		},
	}, &sgtest.DeviceOptions{Now: time.Now()}, t)

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
				TEEDevice:        &SevSnpQuoteProvider{sevTestQp},
			},
			wantReportData: someNonce64,
		},
		{
			name: "Happy case with nonce",
			opts: AttestOpts{
				Nonce:            someNonce,
				CertChainFetcher: localClient,
				TEEDevice:        &SevSnpQuoteProvider{sevTestQp},
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

func TestTdxQuoteProvider(t *testing.T) {
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
	mockTdxQuoteProvider := tgtestclient.GetMockTdxQuoteProvider([]tgtest.TestCase{
		{
			Input: someNonce64,
			Quote: tgtestdata.RawQuote,
		},
		{
			Input: nonce64,
			Quote: tgtestdata.RawQuote,
		},
	}, t)

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
				TEEDevice: &TdxQuoteProvider{mockTdxQuoteProvider},
			},
			wantReportData: someNonce64,
		},
		{
			name: "Happy case with nonce",
			opts: AttestOpts{
				Nonce:     someNonce,
				TEEDevice: &TdxQuoteProvider{mockTdxQuoteProvider},
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
