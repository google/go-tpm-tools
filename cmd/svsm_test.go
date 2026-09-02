package cmd

import (
	"bytes"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"os"
	"strconv"
	"strings"
	"testing"

	epb "github.com/google/gce-tcb-verifier/proto/endorsement"
	"github.com/google/go-configfs-tsm/configfs/configfsi"
	"github.com/google/go-configfs-tsm/configfs/faketsm"
	sabi "github.com/google/go-sev-guest/abi"
	sevpb "github.com/google/go-sev-guest/proto/sevsnp"
	sgtest "github.com/google/go-sev-guest/testing"
	"github.com/google/go-sev-guest/validate"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
)

func TestMakeSVSNPSVSMAttestation(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	ak, err := client.AttestationKeyECC(rwc)
	if err != nil {
		t.Fatalf("failed to create ak: %v", err)
	}
	defer ak.Close()
	akPubBytes, err := ak.PublicArea().Encode()
	if err != nil {
		t.Fatalf("failed to encode ak pub: %v", err)
	}

	var nonce = [16]byte{0}
	attestation, err := ak.Attest(client.AttestOpts{
		SkipTeeAttestation: true,
		Nonce:              nonce[:],
	})
	if err != nil {
		t.Fatalf("failed to create attestation: %v", err)
	}

	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		t.Fatalf("failed to get EK: %v", err)
	}
	defer ek.Close()
	ekBytes, err := ek.PublicArea().Encode()
	if err != nil {
		t.Fatalf("failed to encode EK pub: %v", err)
	}

	var snpNonce [sabi.ReportDataSize]byte
	h := sha512.New()
	h.Write(snpNonce[:])
	h.Write(ekBytes)
	measurement := [48]byte{0}

	configfs := makeFakeConfigfs(h.Sum(nil), ekBytes, 0, measurement[:])
	svsmAttestation, err := makeSEVSNPSVSMAttestation(attestation, &sevSNPSVSMAttestationOpts{
		TEENonce:                   snpNonce[:],
		CongfigfsClient:            configfs,
		VTPMServiceManifestVersion: "0",
	})
	if err != nil {
		t.Fatalf("failed to make SVSM attestation: %v", err)
	}

	endorsement, err := makeEndorsement(measurement[:])
	if err != nil {
		t.Fatalf("failed to make endorsement: %v", err)
	}
	svsmAttestation.LaunchEndorsement = endorsement
	err = verifySEVSNPSVSMAttestation(verifySEVSNPSVSMOpts{
		TEENonce: snpNonce[:],
		AKPub:    akPubBytes,
		EKPub:    ekBytes,
		SevValidateOpts: &validate.Options{GuestPolicy: sabi.SnpPolicy{
			SMT:   true,
			Debug: true,
		}},
	}, svsmAttestation)
	if err != nil {
		t.Fatalf("failed to verify svsm attestation: %v", err)
	}
}

func makeEndorsement(measurement []byte) ([]byte, error) {
	golden := &epb.VMGoldenMeasurement{
		SevSnp: &epb.VMSevSnp{
			SvsmMeasurement: measurement,
		},
	}
	data, err := proto.Marshal(golden)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal golden measurement: %w", err)
	}
	launchEndorsement := &epb.VMLaunchEndorsement{SerializedUefiGolden: data}
	return proto.Marshal(launchEndorsement)
}

func TestSVSMAttestationsErrors(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	ak, err := client.AttestationKeyECC(rwc)
	if err != nil {
		t.Fatalf("failed to create ak: %v", err)
	}
	defer ak.Close()
	akPubBytes, err := ak.PublicArea().Encode()
	if err != nil {
		t.Fatalf("failed to encode ak pub: %v", err)
	}

	var nonce = [16]byte{0}
	attestation, err := ak.Attest(client.AttestOpts{
		SkipTeeAttestation: true,
		Nonce:              nonce[:],
	})
	if err != nil {
		t.Fatalf("failed to create attestation: %v", err)
	}

	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		t.Fatalf("failed to get EK: %v", err)
	}
	defer ek.Close()
	ekBytes, err := ek.PublicArea().Encode()
	if err != nil {
		t.Fatalf("failed to encode EK pub: %v", err)
	}

	var snpNonce [sabi.ReportDataSize]byte
	h := sha512.New()
	h.Write(snpNonce[:])
	h.Write(ekBytes)
	goodReportData := h.Sum(nil)
	goodVmpl := 0
	goodMeasurement := [48]byte{0}
	copy(goodMeasurement[:], "good")
	testcases := []struct {
		name          string
		getConfigfs   func(t *testing.T) configfsi.Client
		wantErrString string
	}{
		{
			name: "Bad report data",
			getConfigfs: func(_ *testing.T) configfsi.Client {
				var snpNonce [sabi.ReportDataSize]byte
				return makeFakeConfigfs(snpNonce[:], ekBytes, goodVmpl, goodMeasurement[:])
			},
			wantErrString: "report field REPORT_DATA",
		},
		{
			name: "Bad VMPL",
			getConfigfs: func(_ *testing.T) configfsi.Client {
				return makeFakeConfigfs(goodReportData, ekBytes, 2, goodMeasurement[:])
			},
			wantErrString: "report VMPL",
		},
		{
			name: "Bad measurement",
			getConfigfs: func(_ *testing.T) configfsi.Client {
				badMeasurement := make([]byte, 48)
				copy(badMeasurement[:], "bad")
				return makeFakeConfigfs(goodReportData, ekBytes, goodVmpl, badMeasurement[:])
			},
			wantErrString: "report field MEASUREMENT",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			svsmAttestation, err := makeSEVSNPSVSMAttestation(attestation, &sevSNPSVSMAttestationOpts{
				TEENonce:                   snpNonce[:],
				CongfigfsClient:            tc.getConfigfs(t),
				VTPMServiceManifestVersion: "0",
			})
			if err != nil {
				t.Fatalf("failed to make SVSM attestation: %v", err)
			}

			endorsement, err := makeEndorsement(goodMeasurement[:])
			if err != nil {
				t.Fatalf("failed to make endorsement: %v", err)
			}
			svsmAttestation.LaunchEndorsement = endorsement

			err = verifySEVSNPSVSMAttestation(verifySEVSNPSVSMOpts{
				TEENonce: snpNonce[:],
				AKPub:    akPubBytes,
				EKPub:    ekBytes,
				SevValidateOpts: &validate.Options{GuestPolicy: sabi.SnpPolicy{
					SMT:   true,
					Debug: true,
				}},
			}, svsmAttestation)
			if err == nil || !strings.Contains(err.Error(), tc.wantErrString) {
				t.Errorf("got err: %v, want err containing: %q", err, tc.wantErrString)
			}
		})
	}
}

var emptyReportV4 = `
	version: 4
	policy: 0xb0000
	signature_algo: 1
	report_data: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01'
	family_id: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	image_id: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	measurement: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	host_data: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	id_key_digest: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	author_key_digest: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	report_id: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	report_id_ma: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	cpuid1eax_fms: 0
	chip_id: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	signature: '\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'
	`

func makeSnpAttestationReport(reportData []byte, vmpl int, measurement []byte) ([]byte, error) {
	reportProto := &sevpb.Report{}
	prototext.Unmarshal([]byte(emptyReportV4), reportProto)
	reportProto.ReportData = reportData
	reportProto.Vmpl = uint32(vmpl)
	reportProto.Measurement = measurement
	return sabi.ReportToAbiBytes(reportProto)
}

func makeFakeConfigfs(reportData []byte, ekPub []byte, vmpl int, measurement []byte) configfsi.Client {
	report := faketsm.Report611(0)
	report.ReadAttr = readFS(reportData, ekPub, vmpl, measurement)
	configfs := &faketsm.Client{Subsystems: map[string]configfsi.Client{
		"report": report,
	}}

	return configfs
}

func makeFakeCerts() ([]byte, error) {
	b := &sgtest.AmdSignerBuilder{
		Extras: map[string][]byte{sabi.ExtraPlatformInfoGUID: []byte("test")},
	}
	s, err := b.TestOnlyCertChain()
	if err != nil {
		return nil, fmt.Errorf("failed to make test cert chain: %v", err)
	}
	certBytes, err := s.CertTableBytes()
	if err != nil {
		return nil, fmt.Errorf("failed to serialize test cert chain: %v", err)
	}
	return certBytes, nil
}

func readFS(reportData []byte, ekPub []byte, vmpl int, measurement []byte) func(*faketsm.ReportEntry, string) ([]byte, error) {
	return func(_ *faketsm.ReportEntry, attr string) ([]byte, error) {
		switch attr {
		case "provider":
			return []byte("fake\n"), nil
		case "auxblob":
			return makeFakeCerts()
		case "outblob":
			return makeSnpAttestationReport(reportData, vmpl, measurement)
		case "privlevel_floor":
			return []byte(strconv.Itoa(vmpl)), nil
		case "manifestblob":
			return ekPub, nil
		}
		return nil, os.ErrNotExist
	}
}

func TestAttestSVSMFlags(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	ExternalTPM = rwc

	tests := []struct {
		name            string
		teeTech         string
		manifestVersion string
		key             string
		wantErrorMsg    string
	}{
		{
			name:            "InvalidTeeTech",
			teeTech:         "bad",
			manifestVersion: "0",
			wantErrorMsg:    errSvsmOnlySupportedWithSevSnp.Error(),
		},
		{
			name:            "InvalidManifestVersion",
			teeTech:         "sev-snp",
			manifestVersion: "2",
			wantErrorMsg:    "invalid manifest version",
		},
		{
			name:            "ValidManifestVersionEmpty",
			teeTech:         "sev-snp",
			manifestVersion: "",
			wantErrorMsg:    "failed to create linuxtsm configfs client",
		},
		{
			name:            "ValidManifestVersionZero",
			teeTech:         "sev-snp",
			manifestVersion: "0",
			wantErrorMsg:    "failed to create linuxtsm configfs client",
		},
		{
			name:            "ValidManifestVersionOne",
			teeTech:         "sev-snp",
			manifestVersion: "1",
			key:             "gceAK",
			wantErrorMsg:    "failed to create attestation key",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			args := []string{"attest", "svsm", "--tee-technology", tc.teeTech, "--manifest-version", tc.manifestVersion}
			if tc.key != "" {
				args = append(args, "--key", tc.key)
			}
			RootCmd.SetArgs(args)
			err := RootCmd.Execute()

			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !strings.Contains(err.Error(), tc.wantErrorMsg) {
				t.Errorf("expected error containing %q, got: %v", tc.wantErrorMsg, err)
			}
		})
	}
}

func TestMakeSVSNPSVSMAttestationManifestVersion(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	ak, err := client.AttestationKeyECC(rwc)
	if err != nil {
		t.Fatalf("failed to create ak: %v", err)
	}
	defer ak.Close()

	var nonce = [16]byte{0}
	attestation, err := ak.Attest(client.AttestOpts{
		SkipTeeAttestation: true,
		Nonce:              nonce[:],
	})
	if err != nil {
		t.Fatalf("failed to create attestation: %v", err)
	}

	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		t.Fatalf("failed to get EK: %v", err)
	}
	defer ek.Close()
	ekBytes, err := ek.PublicArea().Encode()
	if err != nil {
		t.Fatalf("failed to encode EK pub: %v", err)
	}

	var snpNonce [sabi.ReportDataSize]byte
	h := sha512.New()
	h.Write(snpNonce[:])
	h.Write(ekBytes)
	measurement := [48]byte{0}

	configfs := makeFakeConfigfs(h.Sum(nil), ekBytes, 0, measurement[:])

	tests := []struct {
		name        string
		inputVer    string
		expectedVer string
	}{
		{"EmptyDefaultsToZero", "", "0"},
		{"Zero", "0", "0"},
		{"One", "1", "1"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			svsmAttestation, err := makeSEVSNPSVSMAttestation(attestation, &sevSNPSVSMAttestationOpts{
				TEENonce:                   snpNonce[:],
				CongfigfsClient:            configfs,
				VTPMServiceManifestVersion: tc.inputVer,
			})
			if err != nil {
				t.Fatalf("failed to make SVSM attestation: %v", err)
			}
			if svsmAttestation.GetVtpmServiceManifestVersion() != tc.expectedVer {
				t.Errorf("expected manifest version %q, got %q", tc.expectedVer, svsmAttestation.GetVtpmServiceManifestVersion())
			}
		})
	}
}

func wrap2B(data []byte) []byte {
	res := make([]byte, 2+len(data))
	binary.BigEndian.PutUint16(res[:2], uint16(len(data)))
	copy(res[2:], data)
	return res
}

func makeV1Manifest(keys ...[]byte) []byte {
	var buf bytes.Buffer
	var header [8]byte
	binary.BigEndian.PutUint32(header[0:4], 1)
	binary.BigEndian.PutUint32(header[4:8], uint32(len(keys)))
	buf.Write(header[:])
	for _, k := range keys {
		buf.Write(wrap2B(k))
	}
	return buf.Bytes()
}

func TestVerifySVSMAttestationV1(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	ak, err := client.AttestationKeyECC(rwc)
	if err != nil {
		t.Fatalf("failed to create ak: %v", err)
	}
	defer ak.Close()
	akPubBytes, err := ak.PublicArea().Encode()
	if err != nil {
		t.Fatalf("failed to encode ak pub: %v", err)
	}

	var nonce = [16]byte{0}
	attestation, err := ak.Attest(client.AttestOpts{
		SkipTeeAttestation: true,
		Nonce:              nonce[:],
	})
	if err != nil {
		t.Fatalf("failed to create attestation: %v", err)
	}

	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		t.Fatalf("failed to get EK: %v", err)
	}
	defer ek.Close()
	ekBytes, err := ek.PublicArea().Encode()
	if err != nil {
		t.Fatalf("failed to encode EK pub: %v", err)
	}

	// Construct v1 manifest: [Version (4B)][NumKeys (4B)][TPM2B_PUBLIC(AK)][TPM2B_PUBLIC(EK)]
	manifestBytes := makeV1Manifest(akPubBytes, ekBytes)

	var snpNonce [sabi.ReportDataSize]byte
	h := sha512.New()
	h.Write(snpNonce[:])
	h.Write(manifestBytes)
	measurement := [48]byte{0}

	configfs := makeFakeConfigfs(h.Sum(nil), manifestBytes, 0, measurement[:])
	svsmAttestation, err := makeSEVSNPSVSMAttestation(attestation, &sevSNPSVSMAttestationOpts{
		TEENonce:                   snpNonce[:],
		CongfigfsClient:            configfs,
		VTPMServiceManifestVersion: "1",
	})
	if err != nil {
		t.Fatalf("failed to make SVSM attestation: %v", err)
	}

	endorsement, err := makeEndorsement(measurement[:])
	if err != nil {
		t.Fatalf("failed to make endorsement: %v", err)
	}
	svsmAttestation.LaunchEndorsement = endorsement
	err = verifySEVSNPSVSMAttestation(verifySEVSNPSVSMOpts{
		TEENonce: snpNonce[:],
		AKPub:    akPubBytes,
		EKPub:    ekBytes,
		SevValidateOpts: &validate.Options{GuestPolicy: sabi.SnpPolicy{
			SMT:   true,
			Debug: true,
		}},
	}, svsmAttestation)
	if err != nil {
		t.Fatalf("failed to verify svsm attestation: %v", err)
	}
}

func TestSVSMAttestationsV1Errors(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	ak, err := client.AttestationKeyECC(rwc)
	if err != nil {
		t.Fatalf("failed to create ak: %v", err)
	}
	defer ak.Close()
	akPubBytes, err := ak.PublicArea().Encode()
	if err != nil {
		t.Fatalf("failed to encode ak pub: %v", err)
	}

	var nonce = [16]byte{0}
	attestation, err := ak.Attest(client.AttestOpts{
		SkipTeeAttestation: true,
		Nonce:              nonce[:],
	})
	if err != nil {
		t.Fatalf("failed to create attestation: %v", err)
	}

	ek, err := client.EndorsementKeyRSA(rwc)
	if err != nil {
		t.Fatalf("failed to get EK: %v", err)
	}
	defer ek.Close()
	ekBytes, err := ek.PublicArea().Encode()
	if err != nil {
		t.Fatalf("failed to encode EK pub: %v", err)
	}

	var snpNonce [sabi.ReportDataSize]byte
	goodMeasurement := [48]byte{0}
	copy(goodMeasurement[:], "good")

	testcases := []struct {
		name          string
		getConfigfs   func(t *testing.T) configfsi.Client
		wantErrString string
	}{
		{
			name: "AK not in manifest",
			getConfigfs: func(_ *testing.T) configfsi.Client {
				// Manifest only contains EK, not AK
				manifest := makeV1Manifest(ekBytes)
				h := sha512.New()
				h.Write(snpNonce[:])
				h.Write(manifest)
				return makeFakeConfigfs(h.Sum(nil), manifest, 0, goodMeasurement[:])
			},
			wantErrString: errVtpmServiceManifestAkDoesntMatch.Error(),
		},
		{
			name: "EK not in manifest",
			getConfigfs: func(_ *testing.T) configfsi.Client {
				// Manifest only contains AK, not EK
				manifest := makeV1Manifest(akPubBytes)
				h := sha512.New()
				h.Write(snpNonce[:])
				h.Write(manifest)
				return makeFakeConfigfs(h.Sum(nil), manifest, 0, goodMeasurement[:])
			},
			wantErrString: errVtpmServiceManifestEkDoesntMatchV1.Error(),
		},
		{
			name: "Manifest version is not present",
			getConfigfs: func(_ *testing.T) configfsi.Client {
				malformedManifest := []byte{0x01, 0x00} // Only 2 bytes, too short for 4-byte manifest version
				h := sha512.New()
				h.Write(snpNonce[:])
				h.Write(malformedManifest)
				return makeFakeConfigfs(h.Sum(nil), malformedManifest, 0, goodMeasurement[:])
			},
			wantErrString: "malformed service manifest: manifest version is not present",
		},
		{
			name: "Manifest TPM2B_PUBLIC count is not present",
			getConfigfs: func(_ *testing.T) configfsi.Client {
				malformedManifest := []byte{0x00, 0x00, 0x00, 0x01, 0x00, 0x00} // 6 bytes, version present but < 8 bytes
				h := sha512.New()
				h.Write(snpNonce[:])
				h.Write(malformedManifest)
				return makeFakeConfigfs(h.Sum(nil), malformedManifest, 0, goodMeasurement[:])
			},
			wantErrString: "malformed service manifest: manifest TPM2B_PUBLIC count is not present",
		},
		{
			name: "Malformed manifest (unsupported version in payload)",
			getConfigfs: func(_ *testing.T) configfsi.Client {
				var malformedManifest [8]byte
				binary.BigEndian.PutUint32(malformedManifest[0:4], 2) // Version 2
				binary.BigEndian.PutUint32(malformedManifest[4:8], 1)
				h := sha512.New()
				h.Write(snpNonce[:])
				h.Write(malformedManifest[:])
				return makeFakeConfigfs(h.Sum(nil), malformedManifest[:], 0, goodMeasurement[:])
			},
			wantErrString: "unsupported service manifest version in payload: 2, expected 1",
		},
		{
			name: "Count does not match number of keys (fewer keys than count)",
			getConfigfs: func(_ *testing.T) configfsi.Client {
				// Header says count=2, but we only provide 1 key
				var buf bytes.Buffer
				var header [8]byte
				binary.BigEndian.PutUint32(header[0:4], 1)
				binary.BigEndian.PutUint32(header[4:8], 2)
				buf.Write(header[:])
				buf.Write(wrap2B(akPubBytes))
				manifest := buf.Bytes()
				h := sha512.New()
				h.Write(snpNonce[:])
				h.Write(manifest)
				return makeFakeConfigfs(h.Sum(nil), manifest, 0, goodMeasurement[:])
			},
			wantErrString: "malformed service manifest: count does not match number of keys: expected 2 keys, got 1",
		},
		{
			name: "Count does not match number of keys (more keys than count)",
			getConfigfs: func(_ *testing.T) configfsi.Client {
				// Header says count=1, but we provide 2 keys
				var buf bytes.Buffer
				var header [8]byte
				binary.BigEndian.PutUint32(header[0:4], 1)
				binary.BigEndian.PutUint32(header[4:8], 1)
				buf.Write(header[:])
				buf.Write(wrap2B(akPubBytes))
				buf.Write(wrap2B(ekBytes))
				manifest := buf.Bytes()
				h := sha512.New()
				h.Write(snpNonce[:])
				h.Write(manifest)
				return makeFakeConfigfs(h.Sum(nil), manifest, 0, goodMeasurement[:])
			},
			wantErrString: "malformed service manifest: count does not match number of keys:",
		},
		{
			name: "Malformed manifest (too short for key size)",
			getConfigfs: func(_ *testing.T) configfsi.Client {
				var malformedManifest [9]byte // 8-byte header + 1 byte (too short for 2-byte key size)
				binary.BigEndian.PutUint32(malformedManifest[0:4], 1)
				binary.BigEndian.PutUint32(malformedManifest[4:8], 1)
				h := sha512.New()
				h.Write(snpNonce[:])
				h.Write(malformedManifest[:])
				return makeFakeConfigfs(h.Sum(nil), malformedManifest[:], 0, goodMeasurement[:])
			},
			wantErrString: "malformed service manifest: too short to read key size for key 0",
		},
		{
			name: "Malformed manifest (size exceeds remaining bytes)",
			getConfigfs: func(_ *testing.T) configfsi.Client {
				// 8-byte header + 2-byte size (98) + 8 bytes data (keyLen = 100 > 10)
				malformedManifest := make([]byte, 18)
				binary.BigEndian.PutUint32(malformedManifest[0:4], 1)
				binary.BigEndian.PutUint32(malformedManifest[4:8], 1)
				binary.BigEndian.PutUint16(malformedManifest[8:10], 98)
				h := sha512.New()
				h.Write(snpNonce[:])
				h.Write(malformedManifest)
				return makeFakeConfigfs(h.Sum(nil), malformedManifest, 0, goodMeasurement[:])
			},
			wantErrString: "malformed service manifest: size 98 exceeds remaining bytes 8 for key 0",
		},
		{
			name: "Malformed manifest (trailing bytes after count)",
			getConfigfs: func(_ *testing.T) configfsi.Client {
				// Header says count=1, but we provide 1 key + 5 trailing bytes
				manifest := append(makeV1Manifest(akPubBytes), []byte{1, 2, 3, 4, 5}...)
				h := sha512.New()
				h.Write(snpNonce[:])
				h.Write(manifest)
				return makeFakeConfigfs(h.Sum(nil), manifest, 0, goodMeasurement[:])
			},
			wantErrString: "malformed service manifest: count does not match number of keys: 5 trailing bytes after parsing 1 keys",
		},
	}
	for _, tc := range testcases {
		t.Run(tc.name, func(t *testing.T) {
			svsmAttestation, err := makeSEVSNPSVSMAttestation(attestation, &sevSNPSVSMAttestationOpts{
				TEENonce:                   snpNonce[:],
				CongfigfsClient:            tc.getConfigfs(t),
				VTPMServiceManifestVersion: "1",
			})
			if err != nil {
				t.Fatalf("failed to make SVSM attestation: %v", err)
			}

			endorsement, err := makeEndorsement(goodMeasurement[:])
			if err != nil {
				t.Fatalf("failed to make endorsement: %v", err)
			}
			svsmAttestation.LaunchEndorsement = endorsement

			err = verifySEVSNPSVSMAttestation(verifySEVSNPSVSMOpts{
				TEENonce: snpNonce[:],
				AKPub:    akPubBytes,
				EKPub:    ekBytes,
				SevValidateOpts: &validate.Options{GuestPolicy: sabi.SnpPolicy{
					SMT:   true,
					Debug: true,
				}},
			}, svsmAttestation)
			if err == nil || !strings.Contains(err.Error(), tc.wantErrString) {
				t.Errorf("got err: %v, want err containing: %q", err, tc.wantErrString)
			}
		})
	}
}
