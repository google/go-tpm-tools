package cmd

import (
	"crypto/sha512"
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
