package client

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Creates a barebones x509 certificate with the provided issuing URLs and returns its ASN.1 DER encoding.
func getTestCertBytes(t *testing.T, issuingURL []string) ([]byte, error) {
	t.Helper()

	testKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  false,
		MaxPathLenZero:        true,
		IssuingCertificateURL: issuingURL,
	}

	return x509.CreateCertificate(rand.Reader, template, template, testKey.Public(), testKey)
}

func getTestCert(t *testing.T, issuingURL []string) (*x509.Certificate, error) {
	certBytes, err := getTestCertBytes(t, issuingURL)
	if err != nil {
		t.Fatalf("Unable to create test certificate bytes: %v", err)
	}

	return x509.ParseCertificate(certBytes)
}

func TestGetCertificateChainSucceeds(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		certBytes, err := getTestCertBytes(t, nil)
		if err != nil {
			t.Fatalf("Error creating test intermediate certificate: %v", err)
		}

		rw.WriteHeader(http.StatusOK)
		rw.Write(certBytes)
	}))
	defer ts.Close()

	leafCert, err := getTestCert(t, []string{ts.URL})
	if err != nil {
		t.Fatalf("Error creating test leaf certificate: %v", err)
	}
	key := &Key{cert: leafCert}

	certChain, err := key.getCertificateChain()
	if err != nil {
		t.Fatalf("getCertificateChain() returned error: %v", err)
	}

	// Expect only one intermediate certificate retrieved.
	if len(certChain) != 1 {
		t.Errorf("getCertificateChain() did not return the expected number of certificates: got %v, want 1", len(certChain))
	}
}

func TestGetCertificateChainErrors(t *testing.T) {
	testCases := []struct {
		name        string
		handlerFunc func(http.ResponseWriter, *http.Request)
	}{
		{
			name: "Certificate server returns non-OK status",
			handlerFunc: func(rw http.ResponseWriter, r *http.Request) {
				rw.WriteHeader(http.StatusBadRequest)
			},
		},
		{
			name: "Certificate server does not return a certificate",
			handlerFunc: func(rw http.ResponseWriter, r *http.Request) {
				rw.Write([]byte("This is not a certificate."))
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ts := httptest.NewServer(http.HandlerFunc(tc.handlerFunc))
			defer ts.Close()

			leafCert, err := getTestCert(t, []string{ts.URL})
			if err != nil {
				t.Fatalf("Error creating test leaf certificate: %v", err)
			}
			key := &Key{cert: leafCert}

			_, err = key.getCertificateChain()
			if err == nil {
				t.Error("key.getCertificateChain() returned successfully, expected error.")
			} else {
				t.Logf("key.getCertificateChain() returned with error: %v", err)
			}

		})
	}
}
