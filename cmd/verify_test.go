package cmd

import (
	"encoding/hex"
	"os"
	"strings"
	"testing"

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
	t.Cleanup(func() {
		client.CheckedClose(t, rwc)
	})
	ExternalTPM = rwc

	file1 := makeOutputFile(t, "attest")
	file2 := makeOutputFile(t, "verify")
	t.Cleanup(func() { os.RemoveAll(file1) })
	t.Cleanup(func() { os.RemoveAll(file2) })

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
	t.Cleanup(func() {
		client.CheckedClose(t, rwc)
	})
	ExternalTPM = rwc

	file1 := makeOutputFile(t, "attest")
	file2 := makeOutputFile(t, "verify")
	t.Cleanup(func() { os.RemoveAll(file1) })
	t.Cleanup(func() { os.RemoveAll(file2) })

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
	t.Cleanup(func() {
		client.CheckedClose(t, rwc)
	})
	ExternalTPM = rwc

	file1 := makeOutputFile(t, "attest")
	file2 := makeOutputFile(t, "verify")
	t.Cleanup(func() { os.RemoveAll(file1) })
	t.Cleanup(func() { os.RemoveAll(file2) })

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
			t.Cleanup(func() {
				tpm2.NVUndefineSpace(rwc, "", tpm2.HandlePlatform, tpmutil.Handle(getIndex[op.keyAlgo]))
			})

			var dummyInstance = util.Instance{ProjectID: "test-project", ProjectNumber: "1922337278274", Zone: "us-central-1a", InstanceID: "12345678", InstanceName: "default"}
			mock, err := util.NewMetadataServer(dummyInstance)
			if err != nil {
				t.Error(err)
			}
			t.Cleanup(func() { mock.Stop() })

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
	t.Cleanup(func() {
		client.CheckedClose(t, rwc)
	})
	ExternalTPM = rwc

	inputFile := makeOutputFile(t, "attest")
	outputFile := makeOutputFile(t, "attestout")
	t.Cleanup(func() { os.RemoveAll(inputFile) })
	t.Cleanup(func() { os.RemoveAll(outputFile) })
	teenonce := "12345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678"
	tests := []struct {
		name    string
		nonce   string
		teetech string
		wanterr string
	}{
		{"TdxPass", "1234", "tdx", "failed to create tdx quote provider"},
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

func TestTdxAttestation(t *testing.T) {
	dir := t.TempDir()
	file1, err := os.Create(dir + "/attestFile")
	if err != nil {
		t.Fatal(err)
	}
	file2 := makeOutputFile(t, "verifyFile")
	t.Cleanup(func() { os.RemoveAll(file2) })
	tpmNonce := "1234"
	teeNonce := hex.EncodeToString(test.TdxReportData)
	wrongTeeNonce := hex.EncodeToString([]byte("wrongTdxNonce"))
	attestation := createAttestationWithFakeTdx(t, []byte(tpmNonce), test.TdxReportData, t)
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
	}

	for _, op := range tests {
		t.Run(op.name, func(t *testing.T) {
			RootCmd.SetArgs([]string{"verify", "debug", "--nonce", hexTpmNonce, "--input", file1.Name(), "--output", file2, "--tee-nonce", op.tdxNonce, "--format", "textproto"})
			if err := RootCmd.Execute(); (err == nil && op.wantErr != "") ||
				(err != nil && !strings.Contains(err.Error(), op.wantErr)) {
				t.Errorf("Expected error: %v, got: %v", op.wantErr, err)
			}
		})
	}
}

func createAttestationWithFakeTdx(t *testing.T, tpmNonce []byte, teeNonce []byte, tb *testing.T) *pb.Attestation {
	t.Helper()

	rwc := test.GetSimulatorWithLog(tb, test.Ubuntu2204IntelTdxEventLog)
	t.Cleanup(func() {
		client.CheckedClose(tb, rwc)
	})
	ak, err := client.AttestationKeyRSA(rwc)
	if err != nil {
		t.Fatalf("failed to generate AK: %v", err)
	}
	t.Cleanup(ak.Close)
	var teeNonce64 [64]byte
	copy(teeNonce64[:], teeNonce)
	tdxTestDevice := tgtestclient.GetTdxGuest([]tgtest.TestCase{
		{
			Input: teeNonce64,
			Quote: tgtestdata.RawQuote,
		},
	}, tb)

	t.Cleanup(func() { tdxTestDevice.Close() })
	attestation, err := ak.Attest(client.AttestOpts{
		Nonce:     tpmNonce,
		TEEDevice: &client.TdxDevice{Device: tdxTestDevice},
		TEENonce:  teeNonce64[:],
	})
	if err != nil {
		t.Fatalf("failed to attest: %v", err)
	}
	return attestation
}
