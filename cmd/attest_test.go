package cmd

import (
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	sgtest "github.com/google/go-sev-guest/testing"
	sgtestclient "github.com/google/go-sev-guest/testing/client"
	tgtest "github.com/google/go-tdx-guest/testing"
	tgtestclient "github.com/google/go-tdx-guest/testing/client"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
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
	ExternalTPM = rwc
	// Without nonce.
	RootCmd.SetArgs([]string{"attest", "--key", "AK"})
	if err := RootCmd.Execute(); err == nil {
		t.Error("expected not-nil error")
	}
	// With odd length nonce.
	RootCmd.SetArgs([]string{"attest", "--nonce", "12345", "--key", "AK"})
	if err := RootCmd.Execute(); err == nil {
		t.Error("expected not-nil error")
	}
}

func TestAttestPass(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	ExternalTPM = rwc
	tests := []struct {
		name  string
		key   string
		algo  string
		nonce string
	}{
		{"defaultKey", "", "rsa", "1234"},
		{"AKWithRSA", "AK", "rsa", "2222"},
		{"AKWithECC", "AK", "ecc", "2222"},
	}
	for _, op := range tests {
		t.Run(op.name, func(t *testing.T) {
			secretFile1 := makeOutputFile(t, "attest")
			defer os.RemoveAll(secretFile1)
			attestArgs := []string{"attest", "--output", secretFile1}
			if op.key != "" {
				attestArgs = append(attestArgs, "--key", op.key)
			}
			if op.algo != "" {
				attestArgs = append(attestArgs, "--algo", op.algo)
			}
			if op.nonce != "" {
				attestArgs = append(attestArgs, "--nonce", op.nonce)
			}
			RootCmd.SetArgs(attestArgs)
			if err := RootCmd.Execute(); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestFormatFlagPass(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	ExternalTPM = rwc
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
			attestArgs := []string{"attest", "--nonce", op.nonce, "--output", op.report, "--format", op.format}
			RootCmd.SetArgs(attestArgs)
			if err := RootCmd.Execute(); err != nil {
				t.Error(err)
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
	ExternalTPM = rwc
	inputFile := makeOutputFile(t, "attest")
	outputFile := makeOutputFile(t, "attestout")
	defer os.RemoveAll(inputFile)
	defer os.RemoveAll(outputFile)
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
			attestArgs := []string{"attest", "--nonce", op.nonce, "--output", op.report, "--format", op.formatAttest}
			RootCmd.SetArgs(attestArgs)
			if err := RootCmd.Execute(); err != nil {
				t.Error(err)
			}
			debugArgs := []string{"verify", "debug", "--nonce", op.nonce, "--input", op.report, "--output", op.verifiedReport, "--format", op.formatDebug}
			RootCmd.SetArgs(debugArgs)
			if err := RootCmd.Execute(); err == nil {
				t.Error(err)
			}
		})
	}
}

func TestMetadataPass(t *testing.T) {
	var dummyInstance = Instance{ProjectID: "test-project", ProjectNumber: "1922337278274", Zone: "us-central-1a", InstanceID: "12345678", InstanceName: "default"}
	mock, err := NewMetadataServer(dummyInstance)
	if err != nil {
		t.Error(err)
	}
	defer mock.Stop()
	instanceInfo, err := getInstanceInfoFromMetadata()
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
	ExternalTPM = rwc
	secretFile1 := makeOutputFile(t, "attest")
	defer os.RemoveAll(secretFile1)
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

			RootCmd.SetArgs([]string{"attest", "--nonce", op.nonce, "--key", "gceAK", "--algo", op.keyAlgo, "--output", secretFile1, "--format", "binarypb"})
			if err := RootCmd.Execute(); err != nil {
				t.Error(err)
			}
		})
	}
}

func TestTeeTechnologyFail(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	ExternalTPM = rwc

	// value of tee-technology flag should be sev-snp
	RootCmd.SetArgs([]string{"attest", "--nonce", "1234", "--key", "AK", "--tee-nonce", "12345678", "--tee-technology", "sev"})
	if err := RootCmd.Execute(); err == nil {
		t.Error("expected not-nil error")
	}
}

func TestSevAttestTeeNonceFail(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	ExternalTPM = rwc
	// non-nil TEENonce when TEEDevice is nil
	RootCmd.SetArgs([]string{"attest", "--nonce", "1234", "--key", "AK", "--tee-nonce", "12345678", "--tee-technology", ""})
	if err := RootCmd.Execute(); err == nil {
		t.Error("expected not-nil error")
	}

	// TEENonce with length less than 64 bytes.
	sevTestDevice, _, _, _ := sgtestclient.GetSevGuest([]sgtest.TestCase{
		{
			Input: [64]byte{1, 2, 3, 4},
		},
	}, &sgtest.DeviceOptions{Now: time.Now()}, t)
	defer sevTestDevice.Close()

	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		t.Error(err)
	}
	defer ak.Close()
	attestopts := client.AttestOpts{
		Nonce:     []byte{1, 2, 3, 4},
		TEENonce:  []byte{1, 2, 3, 4},
		TEEDevice: &client.SevSnpDevice{Device: sevTestDevice},
	}
	_, err = ak.Attest(attestopts)
	if err == nil {
		t.Error("expected non-nil error")
	}

}

func TestTdxAttestTeeNonceFail(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	ExternalTPM = rwc
	// non-nil TEENonce when TEEDevice is nil
	RootCmd.SetArgs([]string{"attest", "--nonce", "1234", "--key", "AK", "--tee-nonce", "12345678", "--tee-technology", ""})
	if err := RootCmd.Execute(); err == nil {
		t.Error("expected not-nil error")
	}

	// TEENonce with length less than 64 bytes.
	tdxTestDevice := tgtestclient.GetTdxGuest([]tgtest.TestCase{
		{
			Input: [64]byte{1, 2, 3, 4},
		},
	}, t)
	defer tdxTestDevice.Close()

	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		t.Error(err)
	}
	defer ak.Close()
	attestopts := client.AttestOpts{
		Nonce:     []byte{1, 2, 3, 4},
		TEENonce:  []byte{1, 2, 3, 4},
		TEEDevice: &client.TdxDevice{Device: tdxTestDevice},
	}
	_, err = ak.Attest(attestopts)
	if err == nil {
		t.Error("expected non-nil error")
	}
}

func TestHardwareAttestationPass(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	ExternalTPM = rwc

	inputFile := makeOutputFile(t, "attest")
	outputFile := makeOutputFile(t, "attestout")
	defer os.RemoveAll(inputFile)
	defer os.RemoveAll(outputFile)
	teenonce := "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678"
	tests := []struct {
		name    string
		nonce   string
		teetech string
		wanterr string
	}{
		{"TdxPass", "1234", "tdx", "failed to open tdx device"},
		{"SevSnpPass", "1234", "sev-snp", "failed to open sev-snp device"},
	}
	for _, op := range tests {
		t.Run(op.name, func(t *testing.T) {
			attestArgs := []string{"attest", "--nonce", op.nonce, "--output", inputFile, "--format", "textproto", "--tee-nonce", teenonce, "--tee-technology", op.teetech}
			RootCmd.SetArgs(attestArgs)
			if err := RootCmd.Execute(); err != nil {
				if !strings.Contains(err.Error(), op.wanterr) {
					t.Error(err)
				}
			}
		})
	}
}
