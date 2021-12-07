package server

import (
	"crypto"
	"fmt"
	"log"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/simulator"
)

func ExampleVerifyAttestation() {
	// On client machine, generate the TPM quote.
	// TODO: use real TPM.
	simulator, err := simulator.Get()
	if err != nil {
		log.Fatalf("failed to initialize simulator: %v", err)
	}
	defer simulator.Close()

	ak, err := client.AttestationKeyRSA(simulator)
	if err != nil {
		log.Fatalf("failed to generate AK: %v", err)
	}
	defer ak.Close()

	nonce := []byte("super secret nonce")
	attestation, err := ak.Attest(client.AttestOpts{Nonce: nonce})
	if err != nil {
		log.Fatalf("failed to attest: %v", err)
	}

	// TODO: send Attestation proto to verifier

	// verify the attesation proto
	opts := VerifyOpts{
		Nonce:      nonce,
		TrustedAKs: []crypto.PublicKey{ak.PublicKey()},
		AllowSHA1:  true,
	}
	state, err := VerifyAttestation(attestation, opts)
	if err != nil {
		log.Fatalf("failed to verify: %v", err)
	}

	fmt.Println(state)
}
