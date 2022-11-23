package server

import (
	"crypto/x509"
	"encoding/pem"
	"testing"

	"github.com/google/go-tpm-tools/internal/test"
)

func TestGetGCEInstanceInfoWithNilFails(t *testing.T) {
	_, err := GetGCEInstanceInfo(nil)
	if err == nil {
		t.Error("GetGCEInstanceInfo(nil) got nil error, want an error")
	}
}

func TestGetGCEInstanceInfo(t *testing.T) {
	zone := "us-central1-a"
	projectID := "google.com:wuale-gcp-testing"
	var projectNumber uint64 = 117478743145
	for _, certPEM := range test.GCECertPEMs {
		cert := parseCertificatePEM(t, certPEM)
		info, err := GetGCEInstanceInfo(cert)
		if err != nil {
			t.Errorf("GetGCEInstanceInfo failed: %v", err)
		}
		if info.Zone != zone {
			t.Errorf("GetGCEInstanceInfo().Zone = %v, want %v", info.Zone, zone)
		}
		if info.ProjectId != projectID {
			t.Errorf("GetGCEInstanceInfo().ProjectID = %v, want %v", info.ProjectId, projectID)
		}
		if info.ProjectNumber != projectNumber {
			t.Errorf("GetGCEInstanceInfo().ProjectNumber = %v, want %v", info.ProjectNumber, projectNumber)
		}
		if info.InstanceId == 0 {
			t.Error("GetGCEInstanceInfo().InstanceID got 0, want real instance ID")
		}
	}
}

func parseCertificatePEM(t *testing.T, certPEM []byte) *x509.Certificate {
	block, rest := pem.Decode(certPEM)
	if block == nil {
		t.Fatalf("pem.Decode not able to decode cert: %s", certPEM)
	}
	if block.Type != "CERTIFICATE" {
		t.Fatalf("pem.Decode found unexpected PEM type: %s", block.Type)
	}
	if len(rest) > 0 {
		t.Fatalf("pem.Decode found unexpected trailing data in certificate file: %s", certPEM)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("x509.ParseCertificate failed: %v", err)
	}
	return cert
}
