package cmd

import (
	"crypto"
	"encoding/binary"
	"hash"
	"os"
	"testing"
	"time"

	sgtest "github.com/google/go-sev-guest/testing"
	testclient "github.com/google/go-sev-guest/testing/client"
	sv "github.com/google/go-sev-guest/verify"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	"github.com/google/go-tpm-tools/server"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

func getSnpEventLog() []byte {
	pcr0 := uint32(0)
	algorithms := []struct {
		ID         uint16
		DigestSize uint16
		Make       func() hash.Hash
	}{
		{ID: 0x04, DigestSize: 0x14, Make: crypto.SHA1.New},
		{ID: 0xb, DigestSize: 0x20, Make: crypto.SHA256.New},
		{ID: 0xc, DigestSize: 0x30, Make: crypto.SHA384.New},
	}
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
		binary.LittleEndian.PutUint16(algInfo[0:2], alg.ID)
		binary.LittleEndian.PutUint16(algInfo[2:4], alg.DigestSize)
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
			digest := make([]byte, 2+alg.DigestSize)
			binary.LittleEndian.PutUint16(digest[0:2], alg.ID)
			h := alg.Make()
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

	sevSnpEnum := byte(4)
	nonHostEventInfo := []byte{
		'G', 'C', 'E', ' ', 'N', 'o', 'n', 'H', 'o', 's', 't', 'I', 'n', 'f', 'o', 0,
		sevSnpEnum, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	evNonHostInfo := uint32(0x11)
	return writeTpm2Event(withVersionEvent, pcr0, evNonHostInfo, nonHostEventInfo)
}
func TestVerifyNoncePass(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	ExternalTPM = rwc

	file1 := makeOutputFile(t, "attest")
	file2 := makeOutputFile(t, "verify")
	defer os.RemoveAll(file1)
	defer os.RemoveAll(file2)

	RootCmd.SetArgs([]string{"attest", "--nonce", "1234", "--key", "AK", "--teenonce", "", "--output", file1})
	if err := RootCmd.Execute(); err != nil {
		t.Error(err)
	}

	RootCmd.SetArgs([]string{"verify", "debug", "--nonce", "1234", "--input", file1, "--output", file2})
	if err := RootCmd.Execute(); err != nil {
		t.Error(err)
	}
}

func TestVerifyNonceFail(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	ExternalTPM = rwc

	file1 := makeOutputFile(t, "attest")
	file2 := makeOutputFile(t, "verify")
	defer os.RemoveAll(file1)
	defer os.RemoveAll(file2)

	RootCmd.SetArgs([]string{"attest", "--nonce", "1234", "--output", file1})
	if err := RootCmd.Execute(); err != nil {
		t.Error(err)
	}

	RootCmd.SetArgs([]string{"verify", "debug", "--nonce", "4321", "--input", file1, "--output", file2})
	if err := RootCmd.Execute(); err == nil {
		t.Error("expected non-nil error")
	}
}

func TestVerifyWithGCEAK(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	ExternalTPM = rwc

	file1 := makeOutputFile(t, "attest")
	file2 := makeOutputFile(t, "verify")
	defer os.RemoveAll(file1)
	defer os.RemoveAll(file2)

	var template = map[string]tpm2.Public{
		"rsa": GCEAKTemplateRSA(),
		"ecc": GCEAKTemplateECC(),
	}
	tests := []struct {
		name    string
		nonce   string
		keyAlgo string
	}{
		{"gceAK:RSA", "1234", "rsa"},
		{"gceAK:ECC", "1234", "ecc"},
	}
	for _, op := range tests {
		t.Run(op.name, func(t *testing.T) {
			data, err := template[op.keyAlgo].Encode()
			if err != nil {
				t.Fatalf("failed to encode GCEAKTemplateRSA: %v", err)
			}
			err = setGCEAKTemplate(t, rwc, op.keyAlgo, data)
			if err != nil {
				t.Error(err)
			}
			defer tpm2.NVUndefineSpace(rwc, "", tpm2.HandlePlatform, tpmutil.Handle(getIndex[op.keyAlgo]))

			var dummyInstance = Instance{ProjectID: "test-project", ProjectNumber: "1922337278274", Zone: "us-central-1a", InstanceID: "12345678", InstanceName: "default"}
			mock, err := NewMetadataServer(dummyInstance)
			if err != nil {
				t.Error(err)
			}
			defer mock.Stop()

			RootCmd.SetArgs([]string{"attest", "--nonce", op.nonce, "--key", "gceAK", "--algo", op.keyAlgo, "--output", file1, "--format", "binarypb"})
			if err := RootCmd.Execute(); err != nil {
				t.Error(err)
			}

			RootCmd.SetArgs([]string{"verify", "debug", "--nonce", op.nonce, "--input", file1, "--output", file2})
			if err := RootCmd.Execute(); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestVerifySevSnpPass(t *testing.T) {
	rwc := test.GetSimulatorWithLog(t, getSnpEventLog())
	defer client.CheckedClose(t, rwc)
	ExternalTPM = rwc

	nonce := []byte("super secret nonce")
	altNonce := []byte("alternate secret nonce")
	var nonce64 [64]byte
	copy(nonce64[:], altNonce)
	sevTestDevice, goodSnpRoot, _, kdsGetter := testclient.GetSevGuest([]sgtest.TestCase{
		{
			Input:  nonce64,
			Output: sgtest.TestRawReport(nonce64),
		},
	}, &sgtest.DeviceOptions{Now: time.Now()}, t)
	defer sevTestDevice.Close()

	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		t.Error(err)
	}
	defer ak.Close()

	att, err := ak.Attest(client.AttestOpts{
		Nonce:     nonce,
		TEENonce:  nonce64[:],
		TEEDevice: &client.SevSnpDevice{Device: sevTestDevice},
	})
	if err != nil {
		t.Error(err)
	}
	var validateOpts *server.VerifySnpOpts
	validateOpts = &server.VerifySnpOpts{
		Validation: server.SevSnpDefaultValidateOptsForTest(nonce64[:]),
		Verification: &sv.Options{
			Getter:       kdsGetter,
			TrustedRoots: goodSnpRoot,
		},
	}

	_, err = server.VerifyAttestation(att, server.VerifyOpts{Nonce: nonce, TrustedAKs: []crypto.PublicKey{ak.PublicKey()}, TEEOpts: validateOpts})
	if err != nil {
		t.Errorf("expected non nil error")
	}
}

func TestVerifySevSnpFail(t *testing.T) {
	rwc := test.GetSimulatorWithLog(t, getSnpEventLog())
	defer client.CheckedClose(t, rwc)
	ExternalTPM = rwc

	nonce := []byte("super secret nonce")
	altNonce := []byte("alternate secret nonce")
	var nonce64 [64]byte
	copy(nonce64[:], altNonce)
	sevTestDevice, goodSnpRoot, _, kdsGetter := testclient.GetSevGuest([]sgtest.TestCase{
		{
			Input:  nonce64,
			Output: sgtest.TestRawReport(nonce64),
		},
	}, &sgtest.DeviceOptions{Now: time.Now()}, t)
	defer sevTestDevice.Close()

	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		t.Error(err)
	}
	defer ak.Close()

	att, err := ak.Attest(client.AttestOpts{
		Nonce:     nonce,
		TEENonce:  nonce64[:],
		TEEDevice: &client.SevSnpDevice{Device: sevTestDevice},
	})
	if err != nil {
		t.Error(err)
	}

	var validateOpts *server.VerifySnpOpts
	validateOpts = &server.VerifySnpOpts{
		Validation: server.SevSnpDefaultValidateOptsForTest([]byte("different from teenonce")),
		Verification: &sv.Options{
			Getter:       kdsGetter,
			TrustedRoots: goodSnpRoot,
		},
	}

	_, err = server.VerifyAttestation(att, server.VerifyOpts{Nonce: nonce, TrustedAKs: []crypto.PublicKey{ak.PublicKey()}, TEEOpts: validateOpts})
	if err == nil {
		t.Errorf("verifying attestation: %v", err)
	}
}
