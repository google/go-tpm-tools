package internal

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-tpm-tools/internal/test"
)

var localClient = http.DefaultClient

func TestFetchIssuingCertificateSucceeds(t *testing.T) {
	testCA, caKey := test.GetTestCert(t, nil, nil, nil)

	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write(testCA.Raw)
	}))
	defer ts.Close()

	leafCert, _ := test.GetTestCert(t, []string{"invalid.URL", ts.URL}, testCA, caKey)

	cert, err := fetchIssuingCertificate(localClient, leafCert)
	if err != nil || cert == nil {
		t.Errorf("fetchIssuingCertificate() did not find valid intermediate cert: %v", err)
	}
}

func TestFetchIssuingCertificateReturnsErrorIfMalformedCertificateFound(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("these are some random bytes"))
	}))
	defer ts.Close()

	testCA, caKey := test.GetTestCert(t, nil, nil, nil)
	leafCert, _ := test.GetTestCert(t, []string{ts.URL}, testCA, caKey)

	_, err := fetchIssuingCertificate(localClient, leafCert)
	if err == nil {
		t.Fatal("expected fetchIssuingCertificate to fail with malformed cert")
	}
}

func TestGetCertificateChainSucceeds(t *testing.T) {
	// Create CA and corresponding server.
	testCA, caKey := test.GetTestCert(t, nil, nil, nil)

	caServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write(testCA.Raw)
	}))

	defer caServer.Close()

	// Create intermediate cert and corresponding server.
	intermediateCert, intermediateKey := test.GetTestCert(t, []string{caServer.URL}, testCA, caKey)

	intermediateServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write(intermediateCert.Raw)
	}))
	defer intermediateServer.Close()

	// Create leaf cert.
	leafCert, _ := test.GetTestCert(t, []string{intermediateServer.URL}, intermediateCert, intermediateKey)

	certChain, err := GetCertificateChain(leafCert, localClient)
	if err != nil {
		t.Fatal(err)
	}
	if len(certChain) != 2 {
		t.Fatalf("GetCertificateChain did not return the expected number of certificates: got %v, want 2", len(certChain))
	}
}

// TestFetchIssuingCertificateLargeBodyTruncated verifies that a server
// returning a very large body does not cause OOM; the response is limited
// to maxCertBodyBytes and the truncated body fails certificate parsing,
// returning an error rather than exhausting memory.
func TestFetchIssuingCertificateLargeBodyTruncated(t *testing.T) {
	// Serve a body that exceeds maxCertBodyBytes.
	bigServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-cert")
		// Write maxCertBodyBytes + 1 MiB of data.
		payload := make([]byte, maxCertBodyBytes+1024*1024)
		w.Write(payload)
	}))
	defer bigServer.Close()

	testCA, caKey := test.GetTestCert(t, nil, nil, nil)
	leafCert, _ := test.GetTestCert(t, []string{bigServer.URL}, testCA, caKey)

	// GetCertificateChain will fetch the URL and attempt to parse the truncated
	// response as a DER certificate; it must fail with a parse error, not panic.
	_, err := GetCertificateChain(leafCert, localClient)
	if err == nil {
		t.Fatal("expected error parsing oversized body, got nil")
	}
}
