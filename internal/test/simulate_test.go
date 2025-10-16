package test

import (
	"crypto"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/server"
)

func TestGetTPM(t *testing.T) {
	tpm := GetSimulatorWithLog(t, SP800155EventLog)
	defer tpm.Close()
	ak, err := client.AttestationKeyECC(tpm)
	if err != nil {
		t.Fatalf("failed to create key: %v", err)
	}
	nonce := []byte("hello")
	attestation, err := ak.Attest(client.AttestOpts{Nonce: nonce})
	if err != nil {
		t.Fatalf("failed to attest: %v", err)
	}

	_, err = server.VerifyAttestation(attestation, server.VerifyOpts{
		Nonce:      nonce,
		TrustedAKs: []crypto.PublicKey{ak.PublicKey()},
	})
	if err != nil {
		t.Errorf("failed to verify attestation for SP800 155 event log: %v", err)
	}
}
