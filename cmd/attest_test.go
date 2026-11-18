package cmd

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	attestpb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/verifier/util"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"google.golang.org/protobuf/proto"
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

	opts := attestOptions{key: attestKeyAK}
	if _, err := runAttest(context.Background(), rwc, opts); !errors.Is(err, errEmptyNonce) {
		t.Errorf("runAttest(%+v) = %v, want %v", opts, err, errEmptyNonce)
	}
}

func TestAttestPass(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	tests := []struct {
		name  string
		key   attestKeyType
		algo  attestKeyAlgo
		nonce string
	}{
		{"defaultKey", attestKeyAK, attestKeyAlgoRSA, "1234"},
		{"AKWithRSA", attestKeyAK, attestKeyAlgoRSA, "2222"},
		{"AKWithECC", attestKeyAK, attestKeyAlgoECC, "2222"},
	}
	for _, op := range tests {
		t.Run(op.name, func(t *testing.T) {
			nonceBytes, err := hex.DecodeString(op.nonce)
			if err != nil {
				t.Fatal(err)
			}
			opts := attestOptions{
				key:     op.key,
				keyAlgo: op.algo,
				nonce:   nonceBytes,
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
		format         outputFormat
	}{
		{"Format:binary", "abcd", inputFile, outputFile, outputFormatBinaryPB},
		{"Format:textproto", "abcd", inputFile, outputFile, outputFormatTextproto},
	}
	for _, op := range tests {
		t.Run(op.name, func(t *testing.T) {
			nonceBytes, err := hex.DecodeString(op.nonce)
			if err != nil {
				t.Fatal(err)
			}
			opts := attestOptions{
				key:   attestKeyAK,
				nonce: nonceBytes,
			}
			attestation, err := runAttest(context.Background(), rwc, opts)
			if err != nil {
				t.Fatal(err)
			}
			out, err := formatProto(attestation, op.format)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(op.report, out, 0644); err != nil {
				t.Fatal(err)
			}
			debugArgs := []string{"verify", "debug", "--nonce", op.nonce, "--input", op.report, "--output", op.verifiedReport, "--format", op.format.String()}
			if err := execute(debugArgs, nil); err != nil {
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
	tests := []struct {
		name           string
		nonce          string
		report         string
		verifiedReport string
		formatAttest   outputFormat
		formatDebug    string
	}{
		{"Format:binary", "abcd", inputFile, outputFile, outputFormatBinaryPB, "textproto"},
		{"Format:textproto", "abcd", inputFile, outputFile, outputFormatTextproto, "binarypb"},
		{"Format:textproto", "abcd", inputFile, outputFile, outputFormatTextproto, "xyz"},
	}
	for _, op := range tests {
		t.Run(op.name, func(t *testing.T) {

			nonceBytes, err := hex.DecodeString(op.nonce)
			if err != nil {
				t.Fatal(err)
			}
			opts := attestOptions{
				key:   attestKeyAK,
				nonce: nonceBytes,
			}
			attestation, err := runAttest(context.Background(), rwc, opts)
			if err != nil {
				t.Fatal(err)
			}
			out, err := formatProto(attestation, op.formatAttest)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(op.report, out, 0644); err != nil {
				t.Fatal(err)
			}
			debugArgs := []string{"verify", "debug", "--nonce", op.nonce, "--input", op.report, "--output", op.verifiedReport, "--format", op.formatDebug}
			if err := execute(debugArgs, nil); err == nil {
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
		algo    attestKeyAlgo
	}{
		{"gceAK:RSA", "1234", "rsa", attestKeyAlgoRSA},
		{"gceAK:ECC", "1234", "ecc", attestKeyAlgoECC},
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
				key:     attestKeyGCE,
				keyAlgo: op.algo,
				nonce:   nonceBytes,
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

func TestSevAttestTeeNonceFail(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

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
		teetech teeTech
		wanterr string
	}{
		{"TdxPass", "1234", teeTechTDX, "failed to create tdx quote provider"},
		{"SevSnpPass", "1234", teeTechSEVSNP, "failed to create sev-snp quote provider"},
	}
	for _, op := range tests {
		t.Run(op.name, func(t *testing.T) {
			nonceBytes, err := hex.DecodeString(op.nonce)
			if err != nil {
				t.Fatal(err)
			}
			opts := attestOptions{
				key:   attestKeyAK,
				nonce: nonceBytes,
				tee: &teeOptions{
					technology: op.teetech,
					nonce:      teenonce,
				},
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

func TestAttestDefaultsProduceVerifiableBinaryAttestation(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	output := filepath.Join(t.TempDir(), "attestation.binarypb")

	attestArgs := []string{"attest", "--nonce", "1234", "--output", output}
	if err := execute(attestArgs, rwc); err != nil {
		t.Fatalf("execute(%q) = %v, want nil", attestArgs, err)
	}
	verifyArgs := []string{"verify", "debug", "--nonce", "1234", "--input", output, "--output", os.DevNull}
	if err := execute(verifyArgs, nil); err != nil {
		t.Errorf("execute(%q) = %v, want nil", verifyArgs, err)
	}
}

func TestAttestDefaultsToRSAKey(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	output := filepath.Join(t.TempDir(), "attestation.binarypb")

	args := []string{"attest", "--nonce", "1234", "--output", output}
	if err := execute(args, rwc); err != nil {
		t.Fatalf("execute(%q) = %v, want nil", args, err)
	}
	out, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	attestation := &attestpb.Attestation{}
	if err := proto.Unmarshal(out, attestation); err != nil {
		t.Fatal(err)
	}
	akPub, err := tpm2.DecodePublic(attestation.GetAkPub())
	if err != nil {
		t.Fatal(err)
	}
	if akPub.Type != tpm2.AlgRSA {
		t.Errorf("execute(%q) wrote an AK of type %v, want %v", args, akPub.Type, tpm2.AlgRSA)
	}
}

func TestAttestUsesECCKeyForECCAlgo(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	output := filepath.Join(t.TempDir(), "attestation.binarypb")

	args := []string{"attest", "--nonce", "1234", "--algo", "ecc", "--output", output}
	if err := execute(args, rwc); err != nil {
		t.Fatalf("execute(%q) = %v, want nil", args, err)
	}
	out, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	attestation := &attestpb.Attestation{}
	if err := proto.Unmarshal(out, attestation); err != nil {
		t.Fatal(err)
	}
	akPub, err := tpm2.DecodePublic(attestation.GetAkPub())
	if err != nil {
		t.Fatal(err)
	}
	if akPub.Type != tpm2.AlgECC {
		t.Errorf("execute(%q) wrote an AK of type %v, want %v", args, akPub.Type, tpm2.AlgECC)
	}
}

func TestAttestWritesTextproto(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	output := filepath.Join(t.TempDir(), "attestation.textproto")

	attestArgs := []string{"attest", "--nonce", "1234", "--format", "textproto", "--output", output}
	if err := execute(attestArgs, rwc); err != nil {
		t.Fatalf("execute(%q) = %v, want nil", attestArgs, err)
	}
	verifyArgs := []string{"verify", "debug", "--nonce", "1234", "--format", "textproto", "--input", output, "--output", os.DevNull}
	if err := execute(verifyArgs, nil); err != nil {
		t.Errorf("execute(%q) = %v, want nil", verifyArgs, err)
	}
}

func TestAttestWritesToStdoutByDefault(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	args := []string{"attest", "--nonce", "1234"}
	out, err := executeOutput(args, rwc)
	if err != nil {
		t.Fatalf("executeOutput(%q) = %v, want nil", args, err)
	}
	attestation := &attestpb.Attestation{}
	if err := proto.Unmarshal(out, attestation); err != nil {
		t.Fatal(err)
	}
	if _, err := tpm2.DecodePublic(attestation.GetAkPub()); err != nil {
		t.Errorf("executeOutput(%q) wrote no AK public key: %v", args, err)
	}
}

func TestAttestRejectsTEENonceWithoutTEETechnology(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	args := []string{"attest", "--nonce", "1234", "--tee-nonce", "abcd", "--output", os.DevNull}
	want := "use of --tee-nonce requires specifying TEE hardware type with --tee-technology"
	if got := fmt.Sprint(execute(args, rwc)); !strings.Contains(got, want) {
		t.Errorf("execute(%q) = %q, want error containing %q", args, got, want)
	}
}

func TestAttestRejectsUnknownTEETechnology(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	args := []string{"attest", "--nonce", "1234", "--tee-technology", "sev", "--output", os.DevNull}
	want := "tee-technology should be either empty or should have values sev-snp or tdx"
	if got := fmt.Sprint(execute(args, rwc)); !strings.Contains(got, want) {
		t.Errorf("execute(%q) = %q, want error containing %q", args, got, want)
	}
}

func TestAttestRejectsUnknownKey(t *testing.T) {
	args := []string{"attest", "--key", "EK"}
	if err := execute(args, nil); !errors.Is(err, errUnknownKey) {
		t.Errorf("execute(%q) = %v, want %v", args, err, errUnknownKey)
	}
}

func TestAttestRejectsUnknownFormat(t *testing.T) {
	args := []string{"attest", "--format", "json"}
	if err := execute(args, nil); !errors.Is(err, errUnknownFormat) {
		t.Errorf("execute(%q) = %v, want %v", args, err, errUnknownFormat)
	}
}

func TestAttestRejectsUnknownAlgo(t *testing.T) {
	args := []string{"attest", "--algo", "sha256"}
	if err := execute(args, nil); !errors.Is(err, errUnsupportedKeyAlgo) {
		t.Errorf("execute(%q) = %v, want %v", args, err, errUnsupportedKeyAlgo)
	}
}

func TestAttestRejectsOddLengthNonce(t *testing.T) {
	args := []string{"attest", "--nonce", "123"}
	if err := execute(args, nil); !errors.Is(err, hex.ErrLength) {
		t.Errorf("execute(%q) = %v, want %v", args, err, hex.ErrLength)
	}
}

func TestAttestRejectsNonHexNonce(t *testing.T) {
	args := []string{"attest", "--nonce", "zz"}
	var inv hex.InvalidByteError
	if err := execute(args, nil); !errors.As(err, &inv) {
		t.Errorf("execute(%q) = %v, want hex.InvalidByteError", args, err)
	}
}

func TestAttestRejectsOddLengthTEENonce(t *testing.T) {
	args := []string{"attest", "--nonce", "1234", "--tee-nonce", "123"}
	if err := execute(args, nil); !errors.Is(err, hex.ErrLength) {
		t.Errorf("execute(%q) = %v, want %v", args, err, hex.ErrLength)
	}
}
