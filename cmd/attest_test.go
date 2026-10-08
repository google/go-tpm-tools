package cmd

import (
	"context"
	"encoding/hex"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	sgtest "github.com/google/go-sev-guest/testing"
	sgtestclient "github.com/google/go-sev-guest/testing/client"
	tgtest "github.com/google/go-tdx-guest/testing"
	tgtestclient "github.com/google/go-tdx-guest/testing/client"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	"github.com/google/go-tpm-tools/verifier/util"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/spf13/cobra"
)

var getIndex = map[string]uint32{
	"rsa": client.GceAKTemplateNVIndexRSA,
	"ecc": client.GceAKTemplateNVIndexECC,
}

func GCEAKTemplateECC() tpm2.Public {
	return tpm2.Public{
		Type:       tpm2.AlgECC,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSignerDefault,
		ECCParameters: &tpm2.ECCParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgECDSA,
				Hash: tpm2.AlgSHA256,
			},
			CurveID: 3,
		},
	}
}
func GCEAKTemplateRSA() tpm2.Public {
	return tpm2.Public{
		Type:       tpm2.AlgRSA,
		NameAlg:    tpm2.AlgSHA256,
		Attributes: tpm2.FlagSignerDefault,
		RSAParameters: &tpm2.RSAParams{
			Sign: &tpm2.SigScheme{
				Alg:  tpm2.AlgRSASSA,
				Hash: tpm2.AlgSHA256,
			},
			KeyBits: 2048,
		},
	}
}

// Need to call tpm2.NVUndefinespace on the handle with authHandle tpm2.HandlePlatform.
// e.g defer tpm2.NVUndefineSpace(rwc, "", tpm2.HandlePlatform, tpmutil.Handle(client.GceAKTemplateNVIndexRSA))
func setGCEAKTemplate(tb testing.TB, rwc io.ReadWriteCloser, algo string, data []byte) error {
	// Since this mutates the TPM, any tests using real TPMs must skip.
	test.SkipForRealTPM(tb)
	var err error
	idx := tpmutil.Handle(getIndex[algo])
	if err := tpm2.NVDefineSpace(rwc, tpm2.HandlePlatform, idx,
		"", "", nil,
		tpm2.AttrPPWrite|tpm2.AttrPPRead|tpm2.AttrWriteDefine|tpm2.AttrOwnerRead|tpm2.AttrAuthRead|tpm2.AttrPlatformCreate|tpm2.AttrNoDA,
		uint16(len(data))); err != nil {
		tb.Fatalf("NVDefineSpace failed: %v", err)
	}
	err = tpm2.NVWrite(rwc, tpm2.HandlePlatform, idx, "", data, 0)
	if err != nil {
		tb.Fatalf("failed to write NVIndex: %v", err)
	}
	return nil
}

func makeOutputFile(tb testing.TB, output string) string {
	tb.Helper()
	file, err := os.CreateTemp("", output)
	if err != nil {
		tb.Fatal(err)
	}
	defer file.Close()
	return file.Name()
}

func TestNonce(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	if _, err := runAttest(context.Background(), rwc, attestOptions{Key: "AK"}); err == nil {
		t.Error("expected not-nil error")
	}
}

func TestAttestPass(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	tests := []struct {
		name  string
		key   string
		algo  tpm2.Algorithm
		nonce string
	}{
		{"defaultKey", "", tpm2.AlgRSA, "1234"},
		{"AKWithRSA", "AK", tpm2.AlgRSA, "2222"},
		{"AKWithECC", "AK", tpm2.AlgECC, "2222"},
	}
	for _, op := range tests {
		t.Run(op.name, func(t *testing.T) {
			nonceBytes, err := hex.DecodeString(op.nonce)
			if err != nil {
				t.Fatal(err)
			}
			opts := attestOptions{
				Key:     op.key,
				KeyAlgo: op.algo,
				Nonce:   nonceBytes,
			}
			attestation, err := runAttest(context.Background(), rwc, opts)
			if err != nil {
				t.Error(err)
			}
			if attestation == nil {
				t.Error("expected non-nil attestation")
			}
		})
	}
}

func TestFormatFlagPass(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	inputFile := makeOutputFile(t, "attestXYZQ")
	outputFile := makeOutputFile(t, "attestout")
	defer os.RemoveAll(inputFile)
	defer os.RemoveAll(outputFile)
	tests := []struct {
		name           string
		nonce          string
		report         string
		verifiedReport string
		format         string
	}{
		{"Format:binary", "abcd", inputFile, outputFile, "binarypb"},
		{"Format:textproto", "abcd", inputFile, outputFile, "textproto"},
	}
	for _, op := range tests {
		t.Run(op.name, func(t *testing.T) {
			nonceBytes, err := hex.DecodeString(op.nonce)
			if err != nil {
				t.Fatal(err)
			}
			opts := attestOptions{
				Key:   "AK",
				Nonce: nonceBytes,
			}
			attestation, err := runAttest(context.Background(), rwc, opts)
			if err != nil {
				t.Fatal(err)
			}
			out, err := formatAttestation(attestation, op.format)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(op.report, out, 0644); err != nil {
				t.Fatal(err)
			}
			debugArgs := []string{"verify", "debug", "--nonce", op.nonce, "--input", op.report, "--output", op.verifiedReport, "--format", op.format}
			RootCmd.SetArgs(debugArgs)
			if err := RootCmd.Execute(); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestFormatFlagFail(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	inputFile := makeOutputFile(t, "attest")
	outputFile := makeOutputFile(t, "attestout")
	defer os.RemoveAll(inputFile)
	defer os.RemoveAll(outputFile)
	t.Cleanup(func() { format = "binarypb" })
	tests := []struct {
		name           string
		nonce          string
		report         string
		verifiedReport string
		formatAttest   string
		formatDebug    string
	}{
		{"Format:binary", "abcd", inputFile, outputFile, "binarypb", "textproto"},
		{"Format:textproto", "abcd", inputFile, outputFile, "textproto", "binarypb"},
		{"Format:textproto", "abcd", inputFile, outputFile, "textproto", "xyz"},
	}
	for _, op := range tests {
		t.Run(op.name, func(t *testing.T) {

			nonceBytes, err := hex.DecodeString(op.nonce)
			if err != nil {
				t.Fatal(err)
			}
			opts := attestOptions{
				Key:   "AK",
				Nonce: nonceBytes,
			}
			attestation, err := runAttest(context.Background(), rwc, opts)
			if err != nil {
				t.Fatal(err)
			}
			out, err := formatAttestation(attestation, op.formatAttest)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(op.report, out, 0644); err != nil {
				t.Fatal(err)
			}
			debugArgs := []string{"verify", "debug", "--nonce", op.nonce, "--input", op.report, "--output", op.verifiedReport, "--format", op.formatDebug}
			RootCmd.SetArgs(debugArgs)
			if err := RootCmd.Execute(); err == nil {
				t.Error("expected non-nil error")
			}
		})
	}
}

func TestMetadataPass(t *testing.T) {
	var dummyInstance = util.Instance{ProjectID: "test-project", ProjectNumber: "1922337278274", Zone: "us-central-1a", InstanceID: "12345678", InstanceName: "default"}
	mock, err := util.NewMetadataServer(dummyInstance)
	if err != nil {
		t.Error(err)
	}
	defer mock.Stop()
	instanceInfo, err := getInstanceInfoFromMetadata(context.Background())
	if err != nil {
		t.Error(err)
	}
	if instanceInfo.ProjectId != dummyInstance.ProjectID {
		t.Errorf("metadata.ProjectID() = %v, want %v", instanceInfo.ProjectId, dummyInstance.ProjectID)
	}
	projectNumber, err := strconv.ParseUint(dummyInstance.ProjectNumber, 10, 64)
	if err != nil {
		t.Error(err)
	}
	if instanceInfo.ProjectNumber != projectNumber {
		t.Errorf("metadata.NumericProjectID() = %v, want %v", instanceInfo.ProjectNumber, projectNumber)
	}
	if instanceInfo.InstanceName != dummyInstance.InstanceName {
		t.Errorf("metadata.InstanceName() = %v, want %v", instanceInfo.InstanceName, dummyInstance.InstanceName)
	}
	instanceID, err := strconv.ParseUint(dummyInstance.InstanceID, 10, 64)
	if err != nil {
		t.Error(err)
	}
	if instanceInfo.InstanceId != instanceID {
		t.Errorf("metadata.InstanceID() = %v, want %v", instanceInfo.InstanceId, instanceID)
	}
	if instanceInfo.Zone != dummyInstance.Zone {
		t.Errorf("metadata.Zone() = %v, want %v", instanceInfo.Zone, dummyInstance.Zone)
	}
}

func TestAttestWithGCEAK(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	var template = map[string]tpm2.Public{
		"rsa": GCEAKTemplateRSA(),
		"ecc": GCEAKTemplateECC(),
	}
	tests := []struct {
		name    string
		nonce   string
		keyAlgo string
		algo    tpm2.Algorithm
	}{
		{"gceAK:RSA", "1234", "rsa", tpm2.AlgRSA},
		{"gceAK:ECC", "1234", "ecc", tpm2.AlgECC},
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

			nonceBytes, err := hex.DecodeString(op.nonce)
			if err != nil {
				t.Fatal(err)
			}
			opts := attestOptions{
				Key:     "gceAK",
				KeyAlgo: op.algo,
				Nonce:   nonceBytes,
			}
			attestation, err := runAttest(context.Background(), rwc, opts)
			if err != nil {
				t.Error(err)
			}
			if attestation == nil || attestation.GetInstanceInfo() == nil {
				t.Fatal("expected non-nil attestation and instance info")
			}
			if attestation.GetInstanceInfo().GetProjectId() != dummyInstance.ProjectID {
				t.Errorf("got ProjectId %v, want %v", attestation.GetInstanceInfo().GetProjectId(), dummyInstance.ProjectID)
			}
			if attestation.GetInstanceInfo().GetZone() != dummyInstance.Zone {
				t.Errorf("got Zone %v, want %v", attestation.GetInstanceInfo().GetZone(), dummyInstance.Zone)
			}
			if attestation.GetInstanceInfo().GetInstanceName() != dummyInstance.InstanceName {
				t.Errorf("got InstanceName %v, want %v", attestation.GetInstanceInfo().GetInstanceName(), dummyInstance.InstanceName)
			}
		})
	}
}

func TestTeeTechnologyFail(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	opts := attestOptions{
		Key:           "AK",
		Nonce:         []byte{0x12, 0x34},
		TEENonce:      []byte{0x12, 0x34, 0x56, 0x78},
		TEETechnology: "sev",
	}
	if _, err := runAttest(context.Background(), rwc, opts); err == nil {
		t.Error("expected not-nil error")
	}
}

func TestSevAttestTeeNonceFail(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	// non-nil TEENonce when TEEDevice is nil
	opts := attestOptions{
		Key:           "AK",
		Nonce:         []byte{0x12, 0x34},
		TEENonce:      []byte{0x12, 0x34, 0x56, 0x78},
		TEETechnology: "",
	}
	if _, err := runAttest(context.Background(), rwc, opts); err == nil {
		t.Error("expected not-nil error")
	}

	// TEENonce with length less than 64 bytes.
	sevTestQp, _, _, _ := sgtestclient.GetSevQuoteProvider([]sgtest.TestCase{
		{
			Input: [64]byte{1, 2, 3, 4},
		},
	}, &sgtest.DeviceOptions{Now: time.Now()}, t)

	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		t.Error(err)
	}
	defer ak.Close()
	attestopts := client.AttestOpts{
		Nonce:     []byte{1, 2, 3, 4},
		TEENonce:  []byte{1, 2, 3, 4},
		TEEDevice: &client.SevSnpQuoteProvider{QuoteProvider: sevTestQp},
	}
	_, err = ak.Attest(attestopts)
	if err == nil {
		t.Error("expected non-nil error")
	}
}

func TestTdxAttestTeeNonceFail(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	// non-nil TEENonce when TEEDevice is nil
	opts := attestOptions{
		Key:           "AK",
		Nonce:         []byte{0x12, 0x34},
		TEENonce:      []byte{0x12, 0x34, 0x56, 0x78},
		TEETechnology: "",
	}
	if _, err := runAttest(context.Background(), rwc, opts); err == nil {
		t.Error("expected not-nil error")
	}

	// TEENonce with length less than 64 bytes.
	mockTdxQuoteProvider := tgtestclient.GetMockTdxQuoteProvider([]tgtest.TestCase{
		{
			Input: [64]byte{1, 2, 3, 4},
		},
	}, t)

	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		t.Error(err)
	}
	defer ak.Close()
	attestopts := client.AttestOpts{
		Nonce:     []byte{1, 2, 3, 4},
		TEENonce:  []byte{1, 2, 3, 4},
		TEEDevice: &client.TdxQuoteProvider{QuoteProvider: mockTdxQuoteProvider},
	}
	_, err = ak.Attest(attestopts)
	if err == nil {
		t.Error("expected non-nil error")
	}
}

func TestHardwareAttestationPass(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	teenonce, err := hex.DecodeString("12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		nonce   string
		teetech string
		wanterr string
	}{
		{"TdxPass", "1234", "tdx", "failed to create tdx quote provider"},
		{"SevSnpPass", "1234", "sev-snp", "failed to create sev-snp quote provider"},
	}
	for _, op := range tests {
		t.Run(op.name, func(t *testing.T) {
			nonceBytes, err := hex.DecodeString(op.nonce)
			if err != nil {
				t.Fatal(err)
			}
			opts := attestOptions{
				Key:           "AK",
				Nonce:         nonceBytes,
				TEENonce:      teenonce,
				TEETechnology: op.teetech,
			}
			_, err = runAttest(context.Background(), rwc, opts)
			if err == nil {
				t.Errorf("expected error containing %q, got nil", op.wanterr)
			} else if !strings.Contains(err.Error(), op.wanterr) {
				t.Errorf("got %v, want error containing %q", err, op.wanterr)
			}
		})
	}
}

func TestAttestCLI(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	ExternalTPM = rwc
	t.Cleanup(func() { ExternalTPM = nil })

	outputFile := makeOutputFile(t, "attestcli")
	defer os.RemoveAll(outputFile)

	RootCmd.SetArgs([]string{"attest", "--nonce", "1234", "--key", "AK", "--output", outputFile, "--format", "binarypb"})
	if err := RootCmd.Execute(); err != nil {
		t.Fatalf("attest CLI failed: %v", err)
	}

	info, err := os.Stat(outputFile)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() == 0 {
		t.Error("expected non-empty output file from attest CLI")
	}
}

// parseAttestArgs parses args into an attestCmdConfig.
// It creates an isolated command for each call so parallel tests do not share flag state.
func parseAttestArgs(args ...string) (attestCmdConfig, error) {
	cmd := &cobra.Command{}
	addAttestFlags(cmd)
	if err := cmd.ParseFlags(args); err != nil {
		return attestCmdConfig{}, err
	}
	return parseAttestFlags(cmd)
}

func TestParseAttestFlagsDefaults(t *testing.T) {
	t.Parallel()
	got, err := parseAttestArgs()
	if err != nil {
		t.Fatalf("parseAttestArgs() failed: %v", err)
	}
	want := attestCmdConfig{
		opts: attestOptions{
			Key:      "AK",
			KeyAlgo:  tpm2.AlgRSA,
			Nonce:    []byte{},
			TEENonce: []byte{},
		},
		format: "binarypb",
	}
	if diff := cmp.Diff(want, got, cmp.AllowUnexported(attestCmdConfig{})); diff != "" {
		t.Errorf("parseAttestArgs() returned unexpected diff (-want +got):\n%s", diff)
	}
}

func TestParseAttestFlagsAllFlags(t *testing.T) {
	t.Parallel()
	got, err := parseAttestArgs(
		"--key", "gceAK",
		"--algo", "ecc",
		"--nonce", "1234",
		"--tee-nonce", "abcd",
		"--tee-technology", "tdx",
		"--format", "textproto",
		"--output", "out.textproto",
	)
	if err != nil {
		t.Fatalf("parseAttestArgs() failed: %v", err)
	}
	want := attestCmdConfig{
		opts: attestOptions{
			Key:           "gceAK",
			KeyAlgo:       tpm2.AlgECC,
			Nonce:         []byte{0x12, 0x34},
			TEENonce:      []byte{0xab, 0xcd},
			TEETechnology: "tdx",
		},
		format:     "textproto",
		outputPath: "out.textproto",
	}
	if diff := cmp.Diff(want, got, cmp.AllowUnexported(attestCmdConfig{})); diff != "" {
		t.Errorf("parseAttestArgs() returned unexpected diff (-want +got):\n%s", diff)
	}
}

func TestParseAttestFlagsRejectsInvalidValues(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		args []string
	}{
		{"UnknownKey", []string{"--key", "EK"}},
		{"UnknownAlgo", []string{"--algo", "sha256"}},
		{"OddLengthNonce", []string{"--nonce", "123"}},
		{"NonHexNonce", []string{"--nonce", "zz"}},
		{"OddLengthTEENonce", []string{"--tee-nonce", "123"}},
		{"UnknownFormat", []string{"--format", "json"}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := parseAttestArgs(tc.args...); err == nil {
				t.Errorf("parseAttestArgs(%q) succeeded, want error", tc.args)
			}
		})
	}
}
