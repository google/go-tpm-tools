package client

import (
	"crypto/x509"
	"net/http"
	"testing"

	"github.com/google/go-tpm-tools/internal/test"
	pb "github.com/google/go-tpm-tools/proto/attest"
	"google.golang.org/protobuf/proto"
)

var externalClient = http.DefaultClient

func TestNetworkFetchIssuingCertificate(t *testing.T) {
	attestBytes := test.COS85Nonce9009
	att := &pb.Attestation{}
	if err := proto.Unmarshal(attestBytes, att); err != nil {
		t.Fatalf("Failed to unmarshal test attestation: %v", err)
	}

	akCert, err := x509.ParseCertificate(att.AkCert)
	if err != nil {
		t.Fatalf("Error parsing AK Cert: %v", err)
	}

	key := &Key{cert: akCert}

	certChain, err := key.getCertificateChain(externalClient)
	if err != nil {
		t.Error(err)
	}
	if len(certChain) == 0 {
		t.Error("Did not retrieve any certificates.")
	}
}
