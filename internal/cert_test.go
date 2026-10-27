package internal

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
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

// knownRootCert returns a self-signed CA certificate whose SubjectKeyId is
// rootKeyID. Certificates it signs carry rootKeyID as their AuthorityKeyId.
// The root needs a non-empty Subject: x509.CreateCertificate copies the
// parent SubjectKeyId only when issuer and subject names differ.
func knownRootCert(t *testing.T, rootKeyID []byte) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Known Root CA"},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          rootKeyID,
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, test.RootCAKey.Public(), test.RootCAKey)
	if err != nil {
		t.Fatalf("Unable to create root certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("Unable to parse root certificate: %v", err)
	}
	return cert
}

func TestGetAKIntermediateCertsStopsAtKnownRoot(t *testing.T) {
	if len(knownRootKeyIDs) == 0 {
		t.Fatal("knownRootKeyIDs is empty")
	}
	for _, rootKeyID := range knownRootKeyIDs {
		t.Run(hex.EncodeToString(rootKeyID), func(t *testing.T) {
			rootCert := knownRootCert(t, rootKeyID)

			rootServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
				t.Error("GetAKIntermediateCerts fetched the root certificate")
				rw.WriteHeader(http.StatusOK)
				rw.Write(rootCert.Raw)
			}))
			defer rootServer.Close()

			intermediateCert := test.GetTestCert(t, test.IntermediateCAKey, []string{rootServer.URL}, rootCert, test.RootCAKey)
			intermediateServer := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, _ *http.Request) {
				rw.WriteHeader(http.StatusOK)
				rw.Write(intermediateCert.Raw)
			}))
			defer intermediateServer.Close()

			leafCert := test.GetTestCert(t, test.LeafKey, []string{intermediateServer.URL}, intermediateCert, test.IntermediateCAKey)

			certChain, err := GetAKIntermediateCerts(leafCert, localClient)
			if err != nil {
				t.Fatalf("GetAKIntermediateCerts() failed: %v", err)
			}
			if diff := cmp.Diff([][]byte{intermediateCert.Raw}, certChain); diff != "" {
				t.Errorf("GetAKIntermediateCerts() returned unexpected chain (-want +got):\n%s", diff)
			}
		})
	}
}
