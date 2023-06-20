package test

import (
	"io"
	"sync"
	"testing"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// Only open the TPM device once. Reopening the device causes issues on Linux.
var (
	tpm  io.ReadWriteCloser
	lock sync.Mutex
)

// PCR registers that are OK to use in tests (can be reset without reboot)
var (
	DebugPCR       = 16
	ApplicationPCR = 23
)

type noClose struct {
	io.ReadWriter
}

func (n noClose) Close() error {
	return nil
}

type simulatedTpm struct {
	io.ReadWriteCloser
	eventLog []byte
}

func (s simulatedTpm) EventLog() ([]byte, error) {
	return s.eventLog, nil
}

// SkipOnUnsupportedAlg skips the test if the algorithm is not found in the TPM
// capability.
func SkipOnUnsupportedAlg(t testing.TB, rw io.ReadWriter, alg tpm2.Algorithm) {
	moreData := true
	for i := uint32(0); moreData; i++ {
		var err error
		var descs []interface{}
		descs, moreData, err = tpm2.GetCapability(rw, tpm2.CapabilityAlgs, 1, i)
		if err != nil {
			t.Fatalf("Could not get TPM algorithm capability: %v", err)
		}
		for _, desc := range descs {
			if desc.(tpm2.AlgorithmDescription).ID == alg {
				return
			}
		}
		if !moreData {
			break
		}
	}
	t.Skipf("Algorithm %v is not supported by the TPM", alg)
}

// GetTPM is a cross-platform testing helper function that retrives the
// appropriate TPM device from the flags passed into "go test".
//
// If using a test TPM, this will also retrieve a test eventlog. In this case,
// GetTPM extends the test event log's events into the test TPM.
func GetTPM(tb testing.TB) io.ReadWriteCloser {
	tb.Helper()
	if !useRealTPM() {
		return GetSimulatorWithLog(tb, Rhel8EventLog)
	}

	lock.Lock()
	defer lock.Unlock()
	if tpm == nil {
		var err error
		if tpm, err = getRealTPM(); err != nil {
			tb.Fatalf("Failed to open TPM: %v", err)
		}
	}
	return noClose{tpm}
}

// SkipForRealTPM causes a test or benchmark to be skipped if we are not using
// a test TPM. This lets us avoid clobbering important PCRs on a real machine.
func SkipForRealTPM(tb testing.TB) {
	if useRealTPM() {
		tb.Skip("Running against a real TPM, Skipping Test")
	}
}

// GetSimulatorWithLog returns a simulated TPM with PCRs that match the events
// of the passed in eventlog. This allows for testing attestation flows.
func GetSimulatorWithLog(tb testing.TB, eventLog []byte) io.ReadWriteCloser {
	simulator, err := simulator.Get()
	if err != nil {
		tb.Fatalf("Simulator initialization failed: %v", err)
	}
	// Make sure that whatever happens, we close the simulator
	tb.Cleanup(func() {
		if !simulator.IsClosed() {
			tb.Error("simulator was not properly closed")
			if err := simulator.Close(); err != nil {
				tb.Errorf("when closing simulator: %v", err)
			}
		}
	})

	// Extend event log events on simulator TPM.
	simulateEventLogEvents(tb, simulator, eventLog)
	return simulatedTpm{simulator, eventLog}
}

// simulateEventLogEvents simulates the events in the test event log
// "server/test/ubuntu-2104-event-log" by parsing the log
// and manually extending the TPM.
func simulateEventLogEvents(tb testing.TB, rw io.ReadWriter, eventLog []byte) {
	attestEventLog, err := attest.ParseEventLog(eventLog)
	if err != nil {
		tb.Fatalf("Failed to parse test event log: %v", err)
	}

	// TODO: The Ubuntu 21.04 event log also includes SHA384, but this is not yet
	// supported by go-attestation or go-tpm-tools.
	hashAlgs := map[tpm2.Algorithm]attest.HashAlg{
		tpm2.AlgSHA1:   attest.HashSHA1,
		tpm2.AlgSHA256: attest.HashSHA256,
	}

	for tpm2Alg, attestAlg := range hashAlgs {
		events := attestEventLog.Events(attestAlg)
		for _, event := range events {
			extendOnePcr(tb, rw, event.Index, tpm2Alg, event.Digest)
		}
	}
}

func extendOnePcr(tb testing.TB, rw io.ReadWriter, pcr int, hashAlg tpm2.Algorithm, hash []byte) {
	err := tpm2.PCRExtend(rw, tpmutil.Handle(pcr), hashAlg, hash, "")
	if err != nil {
		tb.Fatalf("PCRExtend failed: %v", err)
	}
}
