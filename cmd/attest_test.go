package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
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
	attestpb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/verifier/util"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/testing/protocmp"
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

func TestAttestRejectsEmptyNonce(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	args := []string{"attest", "--output", os.DevNull}
	if err := execute(args, rwc); err == nil {
		t.Errorf("execute(%q) = nil, want non-nil error", args)
	}
}

func TestAttestUsesRSAKeyForRSAAlgo(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	args := []string{"attest", "--nonce", "1234", "--key", "AK", "--algo", "rsa"}
	out, err := executeOutput(args, rwc)
	if err != nil {
		t.Fatalf("executeOutput(%q) = %v, want nil", args, err)
	}
	attestation := &attestpb.Attestation{}
	if err := proto.Unmarshal(out, attestation); err != nil {
		t.Fatalf("proto.Unmarshal() = %v, want nil", err)
	}
	akPub, err := tpm2.DecodePublic(attestation.GetAkPub())
	if err != nil {
		t.Fatalf("tpm2.DecodePublic() = %v, want nil", err)
	}
	if akPub.Type != tpm2.AlgRSA {
		t.Errorf("executeOutput(%q) wrote an AK of type %v, want %v", args, akPub.Type, tpm2.AlgRSA)
	}
}

func TestAttestBinaryRejectedAsTextproto(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	report := filepath.Join(t.TempDir(), "attestation.binarypb")

	attestArgs := []string{"attest", "--nonce", "abcd", "--format", "binarypb", "--output", report}
	if err := execute(attestArgs, rwc); err != nil {
		t.Fatalf("execute(%q) = %v, want nil", attestArgs, err)
	}
	verifyArgs := []string{"verify", "debug", "--nonce", "abcd", "--format", "textproto", "--input", report, "--output", os.DevNull}
	if err := execute(verifyArgs, nil); err == nil {
		t.Errorf("execute(%q) = nil, want non-nil error", verifyArgs)
	}
}

func TestAttestTextprotoRejectedAsBinary(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	report := filepath.Join(t.TempDir(), "attestation.textproto")

	attestArgs := []string{"attest", "--nonce", "abcd", "--format", "textproto", "--output", report}
	if err := execute(attestArgs, rwc); err != nil {
		t.Fatalf("execute(%q) = %v, want nil", attestArgs, err)
	}
	verifyArgs := []string{"verify", "debug", "--nonce", "abcd", "--format", "binarypb", "--input", report, "--output", os.DevNull}
	if err := execute(verifyArgs, nil); err == nil {
		t.Errorf("execute(%q) = nil, want non-nil error", verifyArgs)
	}
}

func TestAttestWithGCEAKPopulatesInstanceInfo(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	data, err := GCEAKTemplateRSA().Encode()
	if err != nil {
		t.Fatalf("GCEAKTemplateRSA().Encode() = %v, want nil", err)
	}
	if err := setGCEAKTemplate(t, rwc, "rsa", data); err != nil {
		t.Fatalf("setGCEAKTemplate() = %v, want nil", err)
	}
	defer tpm2.NVUndefineSpace(rwc, "", tpm2.HandlePlatform, tpmutil.Handle(client.GceAKTemplateNVIndexRSA))

	mock, err := util.NewMetadataServer(util.Instance{
		ProjectID:     "test-project",
		ProjectNumber: "1922337278274",
		Zone:          "us-central-1a",
		InstanceID:    "12345678",
		InstanceName:  "default",
	})
	if err != nil {
		t.Fatalf("util.NewMetadataServer() = %v, want nil", err)
	}
	defer mock.Stop()

	args := []string{"attest", "--nonce", "1234", "--key", "gceAK"}
	out, err := executeOutput(args, rwc)
	if err != nil {
		t.Fatalf("executeOutput(%q) = %v, want nil", args, err)
	}
	attestation := &attestpb.Attestation{}
	if err := proto.Unmarshal(out, attestation); err != nil {
		t.Fatalf("proto.Unmarshal() = %v, want nil", err)
	}
	want := &attestpb.GCEInstanceInfo{
		ProjectId:     "test-project",
		ProjectNumber: 1922337278274,
		Zone:          "us-central-1a",
		InstanceId:    12345678,
		InstanceName:  "default",
	}
	if diff := cmp.Diff(want, attestation.GetInstanceInfo(), protocmp.Transform()); diff != "" {
		t.Errorf("executeOutput(%q) InstanceInfo diff (-want +got):\n%s", args, diff)
	}
}

func TestAttestWithGCEAKUsesRSAKey(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	data, err := GCEAKTemplateRSA().Encode()
	if err != nil {
		t.Fatalf("GCEAKTemplateRSA().Encode() = %v, want nil", err)
	}
	if err := setGCEAKTemplate(t, rwc, "rsa", data); err != nil {
		t.Fatalf("setGCEAKTemplate() = %v, want nil", err)
	}
	defer tpm2.NVUndefineSpace(rwc, "", tpm2.HandlePlatform, tpmutil.Handle(client.GceAKTemplateNVIndexRSA))

	mock, err := util.NewMetadataServer(util.Instance{
		ProjectID:     "test-project",
		ProjectNumber: "1922337278274",
		Zone:          "us-central-1a",
		InstanceID:    "12345678",
		InstanceName:  "default",
	})
	if err != nil {
		t.Fatalf("util.NewMetadataServer() = %v, want nil", err)
	}
	defer mock.Stop()

	wantKey, err := client.GceAttestationKeyRSA(rwc)
	if err != nil {
		t.Fatalf("client.GceAttestationKeyRSA() = %v, want nil", err)
	}
	wantPub, err := wantKey.PublicArea().Encode()
	wantKey.Close()
	if err != nil {
		t.Fatalf("PublicArea().Encode() = %v, want nil", err)
	}

	args := []string{"attest", "--nonce", "1234", "--key", "gceAK", "--algo", "rsa"}
	out, err := executeOutput(args, rwc)
	if err != nil {
		t.Fatalf("executeOutput(%q) = %v, want nil", args, err)
	}
	attestation := &attestpb.Attestation{}
	if err := proto.Unmarshal(out, attestation); err != nil {
		t.Fatalf("proto.Unmarshal() = %v, want nil", err)
	}
	if !bytes.Equal(attestation.GetAkPub(), wantPub) {
		t.Errorf("executeOutput(%q) wrote AK pub %x, want GCE RSA AK pub %x", args, attestation.GetAkPub(), wantPub)
	}
}

func TestAttestWithGCEAKUsesECCKey(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	data, err := GCEAKTemplateECC().Encode()
	if err != nil {
		t.Fatalf("GCEAKTemplateECC().Encode() = %v, want nil", err)
	}
	if err := setGCEAKTemplate(t, rwc, "ecc", data); err != nil {
		t.Fatalf("setGCEAKTemplate() = %v, want nil", err)
	}
	defer tpm2.NVUndefineSpace(rwc, "", tpm2.HandlePlatform, tpmutil.Handle(client.GceAKTemplateNVIndexECC))

	mock, err := util.NewMetadataServer(util.Instance{
		ProjectID:     "test-project",
		ProjectNumber: "1922337278274",
		Zone:          "us-central-1a",
		InstanceID:    "12345678",
		InstanceName:  "default",
	})
	if err != nil {
		t.Fatalf("util.NewMetadataServer() = %v, want nil", err)
	}
	defer mock.Stop()

	wantKey, err := client.GceAttestationKeyECC(rwc)
	if err != nil {
		t.Fatalf("client.GceAttestationKeyECC() = %v, want nil", err)
	}
	wantPub, err := wantKey.PublicArea().Encode()
	wantKey.Close()
	if err != nil {
		t.Fatalf("PublicArea().Encode() = %v, want nil", err)
	}

	args := []string{"attest", "--nonce", "1234", "--key", "gceAK", "--algo", "ecc"}
	out, err := executeOutput(args, rwc)
	if err != nil {
		t.Fatalf("executeOutput(%q) = %v, want nil", args, err)
	}
	attestation := &attestpb.Attestation{}
	if err := proto.Unmarshal(out, attestation); err != nil {
		t.Fatalf("proto.Unmarshal() = %v, want nil", err)
	}
	if !bytes.Equal(attestation.GetAkPub(), wantPub) {
		t.Errorf("executeOutput(%q) wrote AK pub %x, want GCE ECC AK pub %x", args, attestation.GetAkPub(), wantPub)
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

func TestAttestReportsMissingTDXDevice(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	args := []string{"attest", "--nonce", "1234", "--tee-technology", "tdx", "--tee-nonce", strings.Repeat("12", 64), "--output", os.DevNull}
	want := "failed to create tdx quote provider"
	if got := fmt.Sprint(execute(args, rwc)); !strings.Contains(got, want) {
		t.Errorf("execute(%q) = %q, want error containing %q", args, got, want)
	}
}

func TestAttestReportsMissingSEVSNPDevice(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	args := []string{"attest", "--nonce", "1234", "--tee-technology", "sev-snp", "--tee-nonce", strings.Repeat("12", 64), "--output", os.DevNull}
	want := "failed to create sev-snp quote provider"
	if got := fmt.Sprint(execute(args, rwc)); !strings.Contains(got, want) {
		t.Errorf("execute(%q) = %q, want error containing %q", args, got, want)
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
	if err := execute(args, rwc); !errors.Is(err, errTEENonceWithoutTEETechnology) {
		t.Errorf("execute(%q) = %v, want %v", args, err, errTEENonceWithoutTEETechnology)
	}
}

func TestAttestRejectsUnknownTEETechnology(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	args := []string{"attest", "--nonce", "1234", "--tee-technology", "sev", "--output", os.DevNull}
	if err := execute(args, rwc); !errors.Is(err, errUnknownTEETechnology) {
		t.Errorf("execute(%q) = %v, want %v", args, err, errUnknownTEETechnology)
	}
}

func TestFormatAttestationRejectsUnknownFormat(t *testing.T) {
	if _, err := formatAttestation(&attestpb.Attestation{}, "json"); !errors.Is(err, errUnknownFormat) {
		t.Errorf("formatAttestation(_, %q) = %v, want %v", "json", err, errUnknownFormat)
	}
}

func TestCreateAttestationKeyRejectsUnknownKey(t *testing.T) {
	if _, err := createAttestationKey(nil, "EK", tpm2.AlgRSA); !errors.Is(err, errUnknownKey) {
		t.Errorf("createAttestationKey(nil, %q, %v) = %v, want %v", "EK", tpm2.AlgRSA, err, errUnknownKey)
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
	want := `invalid argument "sha256" for "--algo" flag`
	if got := fmt.Sprint(execute(args, nil)); !strings.Contains(got, want) {
		t.Errorf("execute(%q) = %q, want error containing %q", args, got, want)
	}
}

func TestAttestRejectsOddLengthNonce(t *testing.T) {
	args := []string{"attest", "--nonce", "123"}
	want := `invalid argument "123" for "--nonce" flag`
	if got := fmt.Sprint(execute(args, nil)); !strings.Contains(got, want) {
		t.Errorf("execute(%q) = %q, want error containing %q", args, got, want)
	}
}

func TestAttestRejectsNonHexNonce(t *testing.T) {
	args := []string{"attest", "--nonce", "zz"}
	want := `invalid argument "zz" for "--nonce" flag`
	if got := fmt.Sprint(execute(args, nil)); !strings.Contains(got, want) {
		t.Errorf("execute(%q) = %q, want error containing %q", args, got, want)
	}
}

func TestAttestRejectsOddLengthTEENonce(t *testing.T) {
	args := []string{"attest", "--tee-nonce", "123"}
	want := `invalid argument "123" for "--tee-nonce" flag`
	if got := fmt.Sprint(execute(args, nil)); !strings.Contains(got, want) {
		t.Errorf("execute(%q) = %q, want error containing %q", args, got, want)
	}
}
