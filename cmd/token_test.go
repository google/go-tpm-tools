package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cloud.google.com/go/logging"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	"github.com/google/go-tpm-tools/verifier/util"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"github.com/spf13/cobra"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

func TestTokenWithGCEAK(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	test.SkipForRealTPM(t)

	var template = map[string]tpm2.Public{
		"rsa": GCEAKTemplateRSA(),
		"ecc": GCEAKTemplateECC(),
	}
	for algo, pub := range template {
		gceAkTemplate, err := pub.Encode()
		if err != nil {
			t.Fatalf("failed to encode GCE AK template for %s: %v", algo, err)
		}
		if err := setGCEAKCertTemplate(t, rwc, algo, gceAkTemplate); err != nil {
			t.Fatalf("failed to set GCE AK cert template for %s: %v", algo, err)
		}
		defer tpm2.NVUndefineSpace(rwc, "", tpm2.HandlePlatform, tpmutil.Handle(getIndex[algo]))
		defer tpm2.NVUndefineSpace(rwc, "", tpm2.HandlePlatform, tpmutil.Handle(getCertIndex[algo]))
	}
	tests := []struct {
		name string
		algo tpm2.Algorithm
		fail bool
	}{
		{"gceAK:RSA", tpm2.AlgRSA, true},
		{"gceAK:RSA", tpm2.AlgRSA, false},
		{"gceAK:ECC", tpm2.AlgECC, false},
	}
	for _, op := range tests {
		t.Run(op.name, func(t *testing.T) {
			var dummyMetaInstance = util.Instance{ProjectID: "test-project", ProjectNumber: "1922337278274", Zone: "us-central-1a", InstanceID: "12345678", InstanceName: "default"}
			mockMdsServer, err := util.NewMetadataServer(dummyMetaInstance)
			if err != nil {
				t.Error(err)
			}
			defer mockMdsServer.Stop()

			mockAttestationServer, err := util.NewMockAttestationServer()
			if err != nil {
				t.Error(err)
			}
			defer mockAttestationServer.Stop()

			mockCloudLoggingServerAddress, err := newMockCloudLoggingServer()
			if err != nil {
				t.Error(err)
			}
			conn, err := grpc.NewClient(mockCloudLoggingServerAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
			if err != nil {
				t.Fatalf("dialing %q: %v", mockCloudLoggingServerAddress, err)
			}
			defer conn.Close()
			cloudLogClient, err := logging.NewClient(context.Background(), TestProjectID, option.WithGRPCConn(conn))
			if err != nil {
				t.Fatalf("creating cloud logging client: %v", err)
			}
			defer cloudLogClient.Close()

			opts := tokenOptions{
				KeyAlgo:          op.algo,
				VerifierEndpoint: mockAttestationServer.Server.URL,
				CloudLog:         true,
				Audience:         util.FakeCustomAudience,
				HTTPClient:       mockAttestationServer.Server.Client(),
				CloudLogClient:   cloudLogClient,
			}

			if op.fail {
				opts.CustomNonces = []string{"fail test"}
				_, err := runToken(context.Background(), rwc, opts)
				if err == nil || !strings.Contains(err.Error(), "googleapi: Error 400") {
					t.Errorf("runToken() = %v, want error containing %q", err, "googleapi: Error 400")
				}
			} else {
				opts.CustomNonces = []string{util.FakeCustomNonce[0], util.FakeCustomNonce[1]}
				token, err := runToken(context.Background(), rwc, opts)
				if err != nil {
					t.Errorf("runToken() failed: %v", err)
				}
				if len(token) == 0 {
					t.Errorf("expected token output, got empty")
				}
			}
		})
	}
}

func TestCopiedCustomEventLogFile(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	test.SkipForRealTPM(t)

	algo := "rsa"
	var template = map[string]tpm2.Public{
		"rsa": GCEAKTemplateRSA(),
		"ecc": GCEAKTemplateECC(),
	}
	gceAkTemplate, err := template[algo].Encode()
	if err != nil {
		t.Fatalf("failed to encode GCEAKTemplateRSA: %v", err)
	}
	err = setGCEAKCertTemplate(t, rwc, algo, gceAkTemplate)
	if err != nil {
		t.Error(err)
	}
	defer tpm2.NVUndefineSpace(rwc, "", tpm2.HandlePlatform, tpmutil.Handle(getIndex[algo]))
	defer tpm2.NVUndefineSpace(rwc, "", tpm2.HandlePlatform, tpmutil.Handle(getCertIndex[algo]))

	var dummyMetaInstance = util.Instance{ProjectID: "test-project", ProjectNumber: "1922337278274", Zone: "us-central-1a", InstanceID: "12345678", InstanceName: "default"}
	mockMdsServer, err := util.NewMetadataServer(dummyMetaInstance)
	if err != nil {
		t.Error(err)
	}
	defer mockMdsServer.Stop()

	mockAttestationServer, err := util.NewMockAttestationServer()
	if err != nil {
		t.Error(err)
	}
	defer mockAttestationServer.Stop()

	opts := tokenOptions{
		KeyAlgo:          tpm2.AlgRSA,
		VerifierEndpoint: mockAttestationServer.Server.URL,
		EventLog:         test.Cos85AmdSevEventLog,
		HTTPClient:       mockAttestationServer.Server.Client(),
	}

	token, err := runToken(context.Background(), rwc, opts)
	if err != nil {
		t.Errorf("runToken() failed with custom event log: %v", err)
	}
	if len(token) == 0 {
		t.Errorf("expected token output, got empty")
	}
}

func parseTokenFlags(args []string) (tokenOptions, error) {
	var flags tokenFlags
	cmd := &cobra.Command{}
	addTokenFlags(cmd, &flags)
	if err := cmd.ParseFlags(args); err != nil {
		return tokenOptions{}, err
	}
	return flags.parse(cmd.Flags().Changed("event-log"))
}

func TestParseTokenFlagsDefaults(t *testing.T) {
	got, err := parseTokenFlags(nil)
	if err != nil {
		t.Fatalf("parseTokenFlags(nil) = %v, want nil", err)
	}
	want := tokenOptions{
		KeyAlgo:          tpm2.AlgRSA,
		VerifierEndpoint: "https://confidentialcomputing.googleapis.com",
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("parseTokenFlags(nil) returned unexpected diff (-want +got):\n%s", diff)
	}
}

func TestParseTokenFlagsAlgoECC(t *testing.T) {
	args := []string{"--algo", "ecc"}
	got, err := parseTokenFlags(args)
	if err != nil {
		t.Fatalf("parseTokenFlags(%q) = %v, want nil", args, err)
	}
	if got.KeyAlgo != tpm2.AlgECC {
		t.Errorf("parseTokenFlags(%q).KeyAlgo = %v, want %v", args, got.KeyAlgo, tpm2.AlgECC)
	}
}

func TestParseTokenFlagsAudience(t *testing.T) {
	args := []string{"--audience", "https://example.com"}
	got, err := parseTokenFlags(args)
	if err != nil {
		t.Fatalf("parseTokenFlags(%q) = %v, want nil", args, err)
	}
	if got.Audience != "https://example.com" {
		t.Errorf("parseTokenFlags(%q).Audience = %q, want %q", args, got.Audience, "https://example.com")
	}
}

func TestParseTokenFlagsCustomNonces(t *testing.T) {
	args := []string{"--custom-nonce", "nonce-1", "--custom-nonce", "nonce-2"}
	got, err := parseTokenFlags(args)
	if err != nil {
		t.Fatalf("parseTokenFlags(%q) = %v, want nil", args, err)
	}
	want := []string{"nonce-1", "nonce-2"}
	if diff := cmp.Diff(want, got.CustomNonces); diff != "" {
		t.Errorf("parseTokenFlags(%q).CustomNonces returned unexpected diff (-want +got):\n%s", args, diff)
	}
}

func TestParseTokenFlagsCloudLog(t *testing.T) {
	args := []string{"--audience", "https://example.com", "--cloud-log"}
	got, err := parseTokenFlags(args)
	if err != nil {
		t.Fatalf("parseTokenFlags(%q) = %v, want nil", args, err)
	}
	if !got.CloudLog {
		t.Errorf("parseTokenFlags(%q).CloudLog = false, want true", args)
	}
}

func TestParseTokenFlagsRejectsCloudLogWithoutAudience(t *testing.T) {
	args := []string{"--cloud-log"}
	if _, err := parseTokenFlags(args); !errors.Is(err, errCloudLogRequiresAudience) {
		t.Errorf("parseTokenFlags(%q) = %v, want %v", args, err, errCloudLogRequiresAudience)
	}
}

func TestParseTokenFlagsTEETechnologySEVSNP(t *testing.T) {
	args := []string{"--tee-technology", "sev-snp"}
	got, err := parseTokenFlags(args)
	if err != nil {
		t.Fatalf("parseTokenFlags(%q) = %v, want nil", args, err)
	}
	if got.TEETechnology != "sev-snp" {
		t.Errorf("parseTokenFlags(%q).TEETechnology = %q, want %q", args, got.TEETechnology, "sev-snp")
	}
}

func TestParseTokenFlagsTEETechnologyTDX(t *testing.T) {
	args := []string{"--tee-technology", "tdx"}
	got, err := parseTokenFlags(args)
	if err != nil {
		t.Fatalf("parseTokenFlags(%q) = %v, want nil", args, err)
	}
	if got.TEETechnology != "tdx" {
		t.Errorf("parseTokenFlags(%q).TEETechnology = %q, want %q", args, got.TEETechnology, "tdx")
	}
}

func TestParseTokenFlagsRejectsUnknownTEETechnology(t *testing.T) {
	args := []string{"--tee-technology", "sev"}
	if _, err := parseTokenFlags(args); !errors.Is(err, errUnknownTEETech) {
		t.Errorf("parseTokenFlags(%q) = %v, want %v", args, err, errUnknownTEETech)
	}
}

func TestParseTokenFlagsOutput(t *testing.T) {
	args := []string{"--output", "token.jwt"}
	got, err := parseTokenFlags(args)
	if err != nil {
		t.Fatalf("parseTokenFlags(%q) = %v, want nil", args, err)
	}
	if got.OutputPath != "token.jwt" {
		t.Errorf("parseTokenFlags(%q).OutputPath = %q, want %q", args, got.OutputPath, "token.jwt")
	}
}

func TestParseTokenFlagsVerifierEndpoint(t *testing.T) {
	args := []string{"--verifier-endpoint", "https://verifier.example.com"}
	got, err := parseTokenFlags(args)
	if err != nil {
		t.Fatalf("parseTokenFlags(%q) = %v, want nil", args, err)
	}
	if got.VerifierEndpoint != "https://verifier.example.com" {
		t.Errorf("parseTokenFlags(%q).VerifierEndpoint = %q, want %q", args, got.VerifierEndpoint, "https://verifier.example.com")
	}
}

func TestParseTokenFlagsEventLogPath(t *testing.T) {
	args := []string{"--event-log", "/tmp/custom_event_log"}
	opts, err := parseTokenFlags(args)
	if err != nil {
		t.Fatalf("parseTokenFlags(%q) = %v, want nil", args, err)
	}
	if opts.EventLogPath != "/tmp/custom_event_log" {
		t.Errorf("parseTokenFlags(%q).EventLogPath = %q, want %q", args, opts.EventLogPath, "/tmp/custom_event_log")
	}
}

func TestParseTokenFlagsRejectsEmptyEventLogPath(t *testing.T) {
	args := []string{"--event-log", ""}
	if _, err := parseTokenFlags(args); !errors.Is(err, errEmptyEventLogPath) {
		t.Errorf("parseTokenFlags(%q) = %v, want %v", args, err, errEmptyEventLogPath)
	}
}

func TestTokenCmdRejectsInvalidFlags(t *testing.T) {
	args := []string{"token", "--cloud-log"}
	if err := execute(args, nil); !errors.Is(err, errCloudLogRequiresAudience) {
		t.Errorf("execute(%q) = %v, want %v", args, err, errCloudLogRequiresAudience)
	}
}

func TestTokenCmdMissingEventLog(t *testing.T) {
	args := []string{"token", "--event-log", filepath.Join(t.TempDir(), "missing")}
	if err := execute(args, nil); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("execute(%q) = %v, want %v", args, err, os.ErrNotExist)
	}
}

// Need to call tpm2.NVUndefinespace twice on the handle with authHandle tpm2.HandlePlatform.
// e.g defer tpm2.NVUndefineSpace(rwc, "", tpm2.HandlePlatform, tpmutil.Handle(client.GceAKTemplateNVIndexRSA))
// defer tpm2.NVUndefineSpace(rwc, "", tpm2.HandlePlatform, tpmutil.Handle(client.GceAKCertNVIndexRSA))
func setGCEAKCertTemplate(tb testing.TB, rwc io.ReadWriteCloser, algo string, akTemplate []byte) error {
	var err error
	// Write AK template to NV memory
	if err := tpm2.NVDefineSpace(rwc, tpm2.HandlePlatform, tpmutil.Handle(getIndex[algo]),
		"", "", nil,
		tpm2.AttrPPWrite|tpm2.AttrPPRead|tpm2.AttrWriteDefine|tpm2.AttrOwnerRead|tpm2.AttrAuthRead|tpm2.AttrPlatformCreate|tpm2.AttrNoDA,
		uint16(len(akTemplate))); err != nil {
		tb.Fatalf("NVDefineSpace failed: %v", err)
	}
	err = tpm2.NVWrite(rwc, tpm2.HandlePlatform, tpmutil.Handle(getIndex[algo]), "", akTemplate, 0)
	if err != nil {
		tb.Fatalf("failed to write NVIndex: %v", err)
	}

	// create self-signed AK cert
	getAttestationKeyFunc := getAttestationKey[algo]
	attestKey, err := getAttestationKeyFunc(rwc)
	if err != nil {
		tb.Fatalf("Unable to create key: %v", err)
	}
	defer attestKey.Close()
	akCert := test.GetTestCertForKey(tb, attestKey.PublicKey())
	if err = attestKey.SetCert(akCert); err != nil {
		tb.Errorf("SetCert() returned error: %v", err)
	}

	// write test AK cert.
	// size need to be less than 1024 (MAX_NV_BUFFER_SIZE). If not, split before write.
	certASN1 := akCert.Raw
	// write to gceAK slot in NV memory
	if err := tpm2.NVDefineSpace(rwc, tpm2.HandlePlatform, tpmutil.Handle(getCertIndex[algo]),
		"", "", nil,
		tpm2.AttrPPWrite|tpm2.AttrPPRead|tpm2.AttrWriteDefine|tpm2.AttrOwnerRead|tpm2.AttrAuthRead|tpm2.AttrPlatformCreate|tpm2.AttrNoDA,
		uint16(len(certASN1))); err != nil {
		tb.Fatalf("NVDefineSpace failed: %v", err)
	}
	err = tpm2.NVWrite(rwc, tpm2.HandlePlatform, tpmutil.Handle(getCertIndex[algo]), "", certASN1, 0)
	if err != nil {
		tb.Fatalf("failed to write NVIndex: %v", err)
	}

	return nil
}

var getCertIndex = map[string]uint32{
	"rsa": client.GceAKCertNVIndexRSA,
	"ecc": client.GceAKCertNVIndexECC,
}

var getAttestationKey = map[string]func(rw io.ReadWriter) (*client.Key, error){
	"rsa": client.GceAttestationKeyRSA,
	"ecc": client.GceAttestationKeyECC,
}

func TestTokenCmdInvalidAlgo(t *testing.T) {
	err := execute([]string{"token", "--algo", "invalid-algo"}, nil)
	if err == nil || !strings.Contains(err.Error(), "unknown algorithm") {
		t.Errorf("expected unknown algorithm error, got: %v", err)
	}
}

func TestTokenCmdOutputPath(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)

	test.SkipForRealTPM(t)

	algo := "rsa"
	var template = map[string]tpm2.Public{
		"rsa": GCEAKTemplateRSA(),
	}
	gceAkTemplate, err := template[algo].Encode()
	if err != nil {
		t.Fatalf("failed to encode GCEAKTemplateRSA: %v", err)
	}
	err = setGCEAKCertTemplate(t, rwc, algo, gceAkTemplate)
	if err != nil {
		t.Error(err)
	}
	defer tpm2.NVUndefineSpace(rwc, "", tpm2.HandlePlatform, tpmutil.Handle(getIndex[algo]))
	defer tpm2.NVUndefineSpace(rwc, "", tpm2.HandlePlatform, tpmutil.Handle(getCertIndex[algo]))

	var dummyMetaInstance = util.Instance{ProjectID: "test-project", ProjectNumber: "1922337278274", Zone: "us-central-1a", InstanceID: "12345678", InstanceName: "default"}
	mockMdsServer, err := util.NewMetadataServer(dummyMetaInstance)
	if err != nil {
		t.Error(err)
	}
	defer mockMdsServer.Stop()

	mockAttestationServer, err := util.NewMockAttestationServer()
	if err != nil {
		t.Error(err)
	}
	defer mockAttestationServer.Stop()

	outPath := filepath.Join(t.TempDir(), "token.txt")
	root := newGotpmCmd(testTPM(rwc), testHTTPClient(mockAttestationServer.Server.Client()))
	root.SetArgs([]string{"token", "--verifier-endpoint", mockAttestationServer.Server.URL, "--output", outPath})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute() failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty output file")
	}
}

func TestTokenCmdWritesToStdoutByDefault(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	test.SkipForRealTPM(t)

	gceAkTemplate, err := GCEAKTemplateRSA().Encode()
	if err != nil {
		t.Fatalf("failed to encode GCEAKTemplateRSA: %v", err)
	}
	if err := setGCEAKCertTemplate(t, rwc, "rsa", gceAkTemplate); err != nil {
		t.Fatalf("setGCEAKCertTemplate() failed: %v", err)
	}
	defer tpm2.NVUndefineSpace(rwc, "", tpm2.HandlePlatform, tpmutil.Handle(getIndex["rsa"]))
	defer tpm2.NVUndefineSpace(rwc, "", tpm2.HandlePlatform, tpmutil.Handle(getCertIndex["rsa"]))

	dummyMetaInstance := util.Instance{ProjectID: "test-project", ProjectNumber: "1922337278274", Zone: "us-central-1a", InstanceID: "12345678", InstanceName: "default"}
	mockMdsServer, err := util.NewMetadataServer(dummyMetaInstance)
	if err != nil {
		t.Fatalf("NewMetadataServer() failed: %v", err)
	}
	defer mockMdsServer.Stop()

	mockAttestationServer, err := util.NewMockAttestationServer()
	if err != nil {
		t.Fatalf("NewMockAttestationServer() failed: %v", err)
	}
	defer mockAttestationServer.Stop()

	var out bytes.Buffer
	root := newGotpmCmd(testTPM(rwc), testHTTPClient(mockAttestationServer.Server.Client()))
	root.SetOut(&out)
	args := []string{"token", "--verifier-endpoint", mockAttestationServer.Server.URL}
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(%q) = %v, want nil", args, err)
	}
	if !strings.HasSuffix(out.String(), "\n") || len(strings.TrimSpace(out.String())) == 0 {
		t.Errorf("Execute(%q) wrote %q, want non-empty token line", args, out.String())
	}
}

type roundTripperFunc func(*http.Request) (*http.Response, error)

func (f roundTripperFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestTokenCmdEventLog(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	test.SkipForRealTPM(t)

	gceAkTemplate, err := GCEAKTemplateRSA().Encode()
	if err != nil {
		t.Fatalf("failed to encode GCEAKTemplateRSA: %v", err)
	}
	if err := setGCEAKCertTemplate(t, rwc, "rsa", gceAkTemplate); err != nil {
		t.Fatalf("setGCEAKCertTemplate() failed: %v", err)
	}
	defer tpm2.NVUndefineSpace(rwc, "", tpm2.HandlePlatform, tpmutil.Handle(getIndex["rsa"]))
	defer tpm2.NVUndefineSpace(rwc, "", tpm2.HandlePlatform, tpmutil.Handle(getCertIndex["rsa"]))

	dummyMetaInstance := util.Instance{ProjectID: "test-project", ProjectNumber: "1922337278274", Zone: "us-central-1a", InstanceID: "12345678", InstanceName: "default"}
	mockMdsServer, err := util.NewMetadataServer(dummyMetaInstance)
	if err != nil {
		t.Fatalf("NewMetadataServer() failed: %v", err)
	}
	defer mockMdsServer.Stop()

	mockAttestationServer, err := util.NewMockAttestationServer()
	if err != nil {
		t.Fatalf("NewMockAttestationServer() failed: %v", err)
	}
	defer mockAttestationServer.Stop()

	httpClient := mockAttestationServer.Server.Client()
	baseTransport := httpClient.Transport
	var gotEventLog []byte
	httpClient.Transport = roundTripperFunc(func(r *http.Request) (*http.Response, error) {
		if strings.HasSuffix(r.URL.Path, ":verifyAttestation") {
			body, err := io.ReadAll(r.Body)
			if err != nil {
				return nil, err
			}
			r.Body = io.NopCloser(bytes.NewReader(body))
			var req struct {
				TpmAttestation struct {
					TcgEventLog []byte `json:"tcgEventLog"`
				} `json:"tpmAttestation"`
			}
			if err := json.Unmarshal(body, &req); err != nil {
				return nil, err
			}
			gotEventLog = req.TpmAttestation.TcgEventLog
		}
		return baseTransport.RoundTrip(r)
	})

	eventLogPath := filepath.Join(t.TempDir(), "binary_bios_measurements")
	if err := os.WriteFile(eventLogPath, test.Cos85AmdSevEventLog, 0644); err != nil {
		t.Fatalf("os.WriteFile() = %v, want nil", err)
	}

	root := newGotpmCmd(testTPM(rwc), testHTTPClient(httpClient))
	args := []string{"token", "--quiet", "--verifier-endpoint", mockAttestationServer.Server.URL, "--event-log", eventLogPath}
	root.SetArgs(args)
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(%q) = %v, want nil", args, err)
	}
	if diff := cmp.Diff(test.Cos85AmdSevEventLog, gotEventLog); diff != "" {
		t.Errorf("VerifyAttestation TcgEventLog mismatch (-want +got):\n%s", diff)
	}
}
