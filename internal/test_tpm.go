package internal

import (
	"io"
	"io/ioutil"
	"path/filepath"
	"sync"
	"testing"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpm2"
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

// GetTPM is a cross-platform testing helper function that retrives the
// appropriate TPM device from the flags passed into "go test".
//
// If using a test TPM, this will also retrieve a test eventlog. In this case,
// GetTPM extends the test event log's events into the test TPM.
func GetTPM(tb testing.TB) io.ReadWriteCloser {
	tb.Helper()
	if useRealTPM() {
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

	simulator, err := simulator.Get()
	if err != nil {
		tb.Fatalf("Simulator initialization failed: %v", err)
	}
	absPath, err := filepath.Abs("../server/test/ubuntu-2104-event-log")
	if err != nil {
		tb.Fatalf("failed to get abs path: %v", err)
	}
	eventLog, err := ioutil.ReadFile(absPath)
	if err != nil {
		tb.Fatalf("Failed to get test event log: %v", err)
	}

	// Extend event log events on simulator TPM.
	simulateEventLogEvents(tb, simulator, eventLog)
	return simulatedTpm{simulator, eventLog}
}

// simulateEventLogEvents simulates the events in the the test event log
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
