package test

import (
	"encoding/binary"
	"io"
	"sync"
	"testing"

	"github.com/google/go-attestation/attest"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/legacy/tpm2"
	gtpm2 "github.com/google/go-tpm/tpm2"
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
			// EV_NO_ACTION
			if event.Type == 0x03 {
				continue
			}
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

// CreateTpm2EventLog generates a sample event log that is based on gceConfidentialTechnology
func CreateTpm2EventLog(gceConfidentialTechnologyEnum byte) []byte {
	pcr0 := uint32(0)
	algorithms := []gtpm2.TPMIAlgHash{gtpm2.TPMAlgSHA1, gtpm2.TPMAlgSHA256, gtpm2.TPMAlgSHA384}
	specEventInfo := []byte{
		'S', 'p', 'e', 'c', ' ', 'I', 'D', ' ', 'E', 'v', 'e', 'n', 't', '0', '3', 0,
		0, 0, 0, 0, // platformClass
		0,                              // specVersionMinor,
		2,                              // specVersionMajor,
		0,                              // specErrata
		2,                              // uintnSize
		byte(len(algorithms)), 0, 0, 0} // NumberOfAlgorithms
	for _, alg := range algorithms {
		var algInfo [4]byte
		algo, _ := alg.Hash()
		binary.LittleEndian.PutUint16(algInfo[0:2], uint16(alg))
		binary.LittleEndian.PutUint16(algInfo[2:4], uint16(algo.Size()))
		specEventInfo = append(specEventInfo, algInfo[:]...)
	}
	vendorInfoSize := byte(0)
	specEventInfo = append(specEventInfo, vendorInfoSize)

	specEventHeader := make([]byte, 32)
	evNoAction := uint32(0x03)
	binary.LittleEndian.PutUint32(specEventHeader[0:4], pcr0)
	binary.LittleEndian.PutUint32(specEventHeader[4:8], evNoAction)
	binary.LittleEndian.PutUint32(specEventHeader[28:32], uint32(len(specEventInfo)))
	specEvent := append(specEventHeader, specEventInfo...)

	// After the Spec ID Event, all events must use all the specified digest algorithms.
	extendHashes := func(buffer []byte, info []byte) []byte {
		var numberOfDigests [4]byte
		binary.LittleEndian.PutUint32(numberOfDigests[:], uint32(len(algorithms)))
		buffer = append(buffer, numberOfDigests[:]...)
		for _, alg := range algorithms {
			algo, _ := alg.Hash()
			digest := make([]byte, 2+algo.Size())
			binary.LittleEndian.PutUint16(digest[0:2], uint16(alg))
			h := algo.New()
			h.Write(info)
			copy(digest[2:], h.Sum(nil))
			buffer = append(buffer, digest...)
		}
		return buffer
	}
	writeTpm2Event := func(buffer []byte, pcr uint32, eventType uint32, info []byte) []byte {
		header := make([]byte, 8)
		binary.LittleEndian.PutUint32(header[0:4], pcr)
		binary.LittleEndian.PutUint32(header[4:8], eventType)
		buffer = append(buffer, header...)

		buffer = extendHashes(buffer, info)

		var eventSize [4]byte
		binary.LittleEndian.PutUint32(eventSize[:], uint32(len(info)))
		buffer = append(buffer, eventSize[:]...)

		return append(buffer, info...)
	}
	evSCRTMversion := uint32(0x08)
	versionEventInfo := []byte{
		'G', 0, 'C', 0, 'E', 0, ' ', 0,
		'V', 0, 'i', 0, 'r', 0, 't', 0, 'u', 0, 'a', 0, 'l', 0, ' ', 0,
		'F', 0, 'i', 0, 'r', 0, 'm', 0, 'w', 0, 'a', 0, 'r', 0, 'e', 0, ' ', 0,
		'v', 0, '1', 0, 0, 0}
	withVersionEvent := writeTpm2Event(specEvent, pcr0, evSCRTMversion, versionEventInfo)

	nonHostEventInfo := []byte{
		'G', 'C', 'E', ' ', 'N', 'o', 'n', 'H', 'o', 's', 't', 'I', 'n', 'f', 'o', 0,
		gceConfidentialTechnologyEnum, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	evNonHostInfo := uint32(0x11)
	return writeTpm2Event(withVersionEvent, pcr0, evNonHostInfo, nonHostEventInfo)
}
