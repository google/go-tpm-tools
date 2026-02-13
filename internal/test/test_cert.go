package test

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"testing"
	"time"
)

// GetTestCert returns an x509 Certificate with the provided issuingURL and signed with the provided parent certificate and key.
// If parentCert and parentKey are nil, the certificate will be self-signed.
func GetTestCert(t *testing.T, issuingURL []string, parentCert *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
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

// GetTestCertForKey returns an x509 Certificate for the provided public key.
// The certificate is self-signed by a newly generated key.
func GetTestCertForKey(t *testing.T, pubKey crypto.PublicKey) *x509.Certificate {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate signing key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(time.Hour),
	}
	certBytes, err := x509.CreateCertificate(rand.Reader, template, template, pubKey, priv)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return cert
}
