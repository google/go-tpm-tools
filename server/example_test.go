package server

import (
	"log"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
)

func ExampleParseMachineState() {
	// On client machine, generate the TPM quote.
	// TODO: use real TPM.
	simulator, err := simulator.Get()
	if err != nil {
		log.Fatalf("failed to initialize simulator: %v", err)
	}
	defer simulator.Close()

	evtLog, err := client.GetEventLog(simulator)
	if err != nil {
		log.Fatalf("failed to get event log: %v", err)
	}

	pcrs, err := client.ReadPCRs(simulator, client.FullPcrSel(tpm2.AlgSHA1))
	if err != nil {
		log.Fatalf("failed to read PCRs: %v", err)
	}

	// TODO: send event log and PCRs to verifier, potentially in an Attestation proto.

	// Verifier replays the event log.
	// TODO: validate the PCRs against a quote. See the Quote examle.
	_, err = ParseMachineState(evtLog, pcrs)
	if err != nil {
		// TODO: handle parsing or replay error.
		log.Fatalf("failed to read PCRs: %v", err)
	}
	// TODO: use events output of ParseAndVerifyEventLog.
	// Note that replayed PCRs are difficult to use in a trustworthy manner.
	// Prefer to use higher level APIs that operate on events, such as
	// go-attestation's ParseSecurebootState.
}
