package cmd

import (
	"os"
	"strings"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
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

	RootCmd.SetArgs([]string{"attest", "--nonce", "1234", "--key", "AK", "--tee-nonce", "", "--output", file1, "--tee-technology", ""})
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

			RootCmd.SetArgs([]string{"attest", "--nonce", op.nonce, "--key", "gceAK", "--algo", op.keyAlgo, "--output", file1, "--format", "binarypb", "--tee-technology", ""})
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

func TestHwAttestationPass(t *testing.T) {
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
			attestArgs := []string{"attest", "--nonce", op.nonce, "--key", "AK", "--output", inputFile, "--format", "textproto", "--tee-nonce", teenonce, "--tee-technology", op.teetech}
			RootCmd.SetArgs(attestArgs)
			if err := RootCmd.Execute(); err != nil {
				if !strings.Contains(err.Error(), op.wanterr) {
					t.Error(err)
				}
			} else {
				RootCmd.SetArgs([]string{"verify", "debug", "--nonce", op.nonce, "--input", inputFile, "--output", outputFile, "--format", "textproto", "--tee-nonce", teenonce})
				if err := RootCmd.Execute(); err != nil {
					t.Error(err)
				}
			}
		})
	}
}
