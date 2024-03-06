package util

import (
	"bytes"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
)

func TestGetAttestation(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	tests := []struct {
		name       string
		keyFetcher TpmKeyFetcher
	}{
		{"RSA", client.AttestationKeyRSA},
		{"ECC", client.AttestationKeyECC},
	}
	for _, op := range tests {
		t.Run(op.name, func(t *testing.T) {
			attestation, err := GetAttestation(rwc, op.keyFetcher, []byte("test"))
			if err != nil {
				t.Errorf("Failed to get attestation %s", err)
			}
			if !bytes.Equal(attestation.EventLog, test.Rhel8EventLog) {
				t.Errorf("attestation event log mismatch %s", err)
			}
		})
	}
}
