package cmd

import (
	"context"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/spf13/cobra"

	tgtest "github.com/google/go-tdx-guest/testing"
	tgtestclient "github.com/google/go-tdx-guest/testing/client"
	tgtestdata "github.com/google/go-tdx-guest/testing/testdata"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	pb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/verifier/util"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

func TestVerifyNoncePass(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	ExternalTPM = rwc

	file1 := makeOutputFile(t, "attest")
	file2 := makeOutputFile(t, "verify")
	defer os.RemoveAll(file1)
	defer os.RemoveAll(file2)

	if err := execute(t, []string{"attest", "--nonce", "1234", "--key", "AK", "--tee-nonce", "", "--output", file1, "--tee-technology", ""}); err != nil {
		t.Error(err)
	}

	if err := execute(t, []string{"verify", "debug", "--nonce", "1234", "--input", file1, "--output", file2}); err != nil {
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

	if err := execute(t, []string{"attest", "--nonce", "1234", "--output", file1}); err != nil {
		t.Error(err)
	}

	if err := execute(t, []string{"verify", "debug", "--nonce", "4321", "--input", file1, "--output", file2}); err == nil {
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

			var dummyInstance = util.Instance{ProjectID: "test-project", ProjectNumber: "1922337278274", Zone: "us-central-1a", InstanceID: "12345678", InstanceName: "default"}
			mock, err := util.NewMetadataServer(dummyInstance)
			if err != nil {
				t.Error(err)
			}
			defer mock.Stop()

			if err := execute(t, []string{"attest", "--nonce", op.nonce, "--key", "gceAK", "--algo", op.keyAlgo, "--output", file1, "--format", "binarypb", "--tee-technology", ""}); err != nil {
				t.Error(err)
			}

			if err := execute(t, []string{"verify", "debug", "--nonce", op.nonce, "--input", file1, "--output", file2}); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestHwAttestationPass(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	teeNonceBytes, err := hex.DecodeString("12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678")
	if err != nil {
		t.Fatal(err)
	}
	nonceBytes := []byte{0x12, 0x34}
	tests := []struct {
		name        string
		teeTech     string
		noDeviceErr string
	}{
		{
			name:        "TdxPass",
			teeTech:     "tdx",
			noDeviceErr: "failed to create tdx quote provider",
		},
		{
			name:        "SevSnpPass",
			teeTech:     "sev-snp",
			noDeviceErr: "failed to create sev-snp quote provider",
		},
	}
	for _, op := range tests {
		t.Run(op.name, func(t *testing.T) {
			opts := attestOptions{
				key:           "AK",
				nonce:         nonceBytes,
				teeNonce:      teeNonceBytes,
				teeTechnology: op.teeTech,
			}
			attestation, err := runAttest(context.Background(), rwc, opts)
			if err != nil {
				if strings.Contains(err.Error(), op.noDeviceErr) {
					t.Skipf("no %s device available: %v", op.teeTech, err)
				}
				t.Fatalf("runAttest() failed: %v", err)
			}
			ms, err := runVerify(attestation, nonceBytes, teeNonceBytes)
			if err != nil {
				t.Fatalf("runVerify() failed: %v", err)
			}
			if ms.GetTeeAttestation() == nil {
				t.Error("ms.GetTeeAttestation() = nil, want non-nil")
			}
		})
	}
}

func TestTdxAttestation(t *testing.T) {
	dir := t.TempDir()
	file1, err := os.Create(dir + "/attestFile")
	if err != nil {
		t.Fatal(err)
	}
	file2 := makeOutputFile(t, "verifyFile")
	defer os.RemoveAll(file2)
	tpmNonce := "1234"
	teeNonce := hex.EncodeToString(test.TdxReportData)
	wrongTeeNonce := hex.EncodeToString([]byte("wrongTdxNonce"))
	attestation, err := createAttestationWithFakeTdx([]byte(tpmNonce), test.TdxReportData, t)
	if err != nil {
		t.Fatal(err)
	}
	out := []byte(marshalOptions.Format(attestation))
	file1.Write(out)
	hexTpmNonce := hex.EncodeToString([]byte(tpmNonce))
	tests := []struct {
		name     string
		tdxNonce string
		wantErr  string
	}{
		{"Correct TEE Nonce", teeNonce, ""},
		{"Incorrect TEE Nonce", wrongTeeNonce, "quote field REPORT_DATA"},
		{"Incorrect Nonce Using TPM Nonce", "", "quote field REPORT_DATA"},
	}

	for _, op := range tests {
		t.Run(op.name, func(t *testing.T) {
			if err := execute(t, []string{"verify", "debug", "--nonce", hexTpmNonce, "--input", file1.Name(), "--output", file2, "--tee-nonce", op.tdxNonce, "--format", "textproto"}); (err == nil && op.wantErr != "") ||
				(err != nil && !strings.Contains(err.Error(), op.wantErr)) {
				t.Errorf("Expected error: %v, got: %v", op.wantErr, err)
			}
		})
	}
}

func createAttestationWithFakeTdx(tpmNonce []byte, teeNonce []byte, tb *testing.T) (*pb.Attestation, error) {
	tdxEventLog := test.CreateTpm2EventLog(3) // Enum 3- TDX
	rwc := test.GetSimulatorWithLog(tb, tdxEventLog)
	defer client.CheckedClose(tb, rwc)
	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		return nil, fmt.Errorf("failed to generate AK: %v", err)
	}
	defer ak.Close()
	var teeNonce64 [64]byte
	copy(teeNonce64[:], teeNonce)
	tdxTestDevice := tgtestclient.GetTdxGuest([]tgtest.TestCase{
		{
			Input: teeNonce64,
			Quote: tgtestdata.RawQuote,
		},
	}, tb)

	defer tdxTestDevice.Close()
	attestation, err := ak.Attest(client.AttestOpts{
		Nonce:     tpmNonce,
		TEEDevice: &client.TdxDevice{Device: tdxTestDevice},
		TEENonce:  teeNonce64[:],
	})
	if err != nil {
		return nil, fmt.Errorf("failed to attest: %v", err)
	}
	return attestation, nil
}

func parseVerifyDebugArgs(args ...string) (verifyDebugConfig, error) {
	cmd := &cobra.Command{}
	flags := cmd.PersistentFlags()
	flags.BytesHex("nonce", []byte{}, "")
	flags.BytesHex("tee-nonce", []byte{}, "")
	flags.String("format", "binarypb", "")
	flags.String("input", "", "")
	flags.String("output", "", "")
	if err := cmd.ParseFlags(args); err != nil {
		return verifyDebugConfig{}, err
	}
	return parseVerifyDebugFlags(cmd)
}

func TestParseVerifyDebugFlagsDefaults(t *testing.T) {
	got, err := parseVerifyDebugArgs("--nonce", "1234")
	if err != nil {
		t.Fatalf("parseVerifyDebugArgs() failed: %v", err)
	}
	want := verifyDebugConfig{
		tpmNonce: []byte{0x12, 0x34},
		teeNonce: []byte{0x12, 0x34},
		format:   "binarypb",
	}
	if diff := cmp.Diff(want, got, cmp.AllowUnexported(verifyDebugConfig{})); diff != "" {
		t.Errorf("parseVerifyDebugArgs() returned unexpected diff (-want +got):\n%s", diff)
	}
}

func TestParseVerifyDebugFlagsExplicitTEENonce(t *testing.T) {
	got, err := parseVerifyDebugArgs(
		"--nonce", "1234",
		"--tee-nonce", "abcd",
		"--format", "textproto",
		"--input", "in.pb",
		"--output", "out.pb",
	)
	if err != nil {
		t.Fatalf("parseVerifyDebugArgs() failed: %v", err)
	}
	want := verifyDebugConfig{
		tpmNonce:   []byte{0x12, 0x34},
		teeNonce:   []byte{0xab, 0xcd},
		format:     "textproto",
		inputPath:  "in.pb",
		outputPath: "out.pb",
	}
	if diff := cmp.Diff(want, got, cmp.AllowUnexported(verifyDebugConfig{})); diff != "" {
		t.Errorf("parseVerifyDebugArgs() returned unexpected diff (-want +got):\n%s", diff)
	}
}

func TestParseVerifyDebugFlagsRejectsInvalidValues(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{"OddLengthNonce", []string{"--nonce", "123"}},
		{"NonHexNonce", []string{"--nonce", "zz"}},
		{"OddLengthTEENonce", []string{"--nonce", "1234", "--tee-nonce", "123"}},
		{"NonHexTEENonce", []string{"--nonce", "1234", "--tee-nonce", "zz"}},
		{"UnknownFormat", []string{"--nonce", "1234", "--format", "json"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := parseVerifyDebugArgs(tc.args...); err == nil {
				t.Errorf("parseVerifyDebugArgs(%q) succeeded, want error", tc.args)
			}
		})
	}
}
