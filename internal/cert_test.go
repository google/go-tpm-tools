package internal

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-tpm-tools/internal/test"
)

var localClient = http.DefaultClient

func TestFetchIssuingCertificateSucceeds(t *testing.T) {
	testCA := test.GetTestCert(t, test.RootCAKey, nil, nil, nil)

	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write(testCA.Raw)
	}))
	defer ts.Close()

	leafCert := test.GetTestCert(t, test.LeafKey, []string{"invalid.URL", ts.URL}, testCA, test.RootCAKey)

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

	testCA := test.GetTestCert(t, test.RootCAKey, nil, nil, nil)
	leafCert := test.GetTestCert(t, test.LeafKey, []string{ts.URL}, testCA, test.RootCAKey)

	_, err := fetchIssuingCertificate(localClient, leafCert)
	if err == nil {
		t.Fatal("expected fetchIssuingCertificate to fail with malformed cert")
	}
}

func TestGetAKIntermediateCertsSucceeds(t *testing.T) {
	// Create CA and corresponding server.
	testCA := test.GetTestCert(t, test.RootCAKey, nil, nil, nil)

	caServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write(testCA.Raw)
	}))

	defer caServer.Close()

	// Create intermediate cert and corresponding server.
	intermediateCert := test.GetTestCert(t, test.IntermediateCAKey, []string{caServer.URL}, testCA, test.RootCAKey)

	intermediateServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write(intermediateCert.Raw)
	}))
	defer intermediateServer.Close()

	// Create leaf cert.
	leafCert := test.GetTestCert(t, test.LeafKey, []string{intermediateServer.URL}, intermediateCert, test.IntermediateCAKey)

	certChain, err := GetAKIntermediateCerts(leafCert, localClient)
	if err != nil {
		t.Fatal(err)
	}
	if len(certChain) != 2 {
		t.Fatalf("GetAKIntermediateCerts did not return the expected number of certificates: got %v, want 2", len(certChain))
	}
}
