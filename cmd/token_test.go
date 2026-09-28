package cmd

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"cloud.google.com/go/logging"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	"github.com/google/go-tpm-tools/verifier/util"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
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

			mockOauth2Server, err := util.NewMockOauth2Server()
			if err != nil {
				t.Error(err)
			}
			defer mockOauth2Server.Stop()

			// Endpoint is Google's OAuth 2.0 default endpoint. Change to mock server.
			google.Endpoint = oauth2.Endpoint{
				AuthURL:   mockOauth2Server.Server.URL + "/o/oauth2/auth",
				TokenURL:  mockOauth2Server.Server.URL + "/token",
				AuthStyle: oauth2.AuthStyleInParams,
			}

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

			opts := TokenOptions{
				KeyAlgo:          op.algo,
				VerifierEndpoint: mockAttestationServer.Server.URL,
				CloudLog:         true,
				Audience:         util.FakeCustomAudience,
				CloudLogClient:   cloudLogClient,
			}

			if op.fail {
				opts.CustomNonces = []string{"fail test"}
				if _, err := RunToken(context.Background(), rwc, opts); err != nil && !strings.Contains(err.Error(), "googleapi: Error 400") {
					t.Errorf("RunToken() returned unexpected error: %v", err)
				}
			} else {
				opts.CustomNonces = []string{util.FakeCustomNonce[0], util.FakeCustomNonce[1]}
				token, err := RunToken(context.Background(), rwc, opts)
				if err != nil {
					t.Errorf("RunToken() failed: %v", err)
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

	mockOauth2Server, err := util.NewMockOauth2Server()
	if err != nil {
		t.Error(err)
	}
	defer mockOauth2Server.Stop()

	// Endpoint is Google's OAuth 2.0 default endpoint. Change to mock server.
	google.Endpoint = oauth2.Endpoint{
		AuthURL:   mockOauth2Server.Server.URL + "/o/oauth2/auth",
		TokenURL:  mockOauth2Server.Server.URL + "/token",
		AuthStyle: oauth2.AuthStyleInParams,
	}

	mockAttestationServer, err := util.NewMockAttestationServer()
	if err != nil {
		t.Error(err)
	}
	defer mockAttestationServer.Stop()

	tmpDir := t.TempDir()
	destPath := filepath.Join(tmpDir, "copied_binary_bios_measurements")
	if err := os.WriteFile(destPath, test.Cos85AmdSevEventLog, 0644); err != nil {
		t.Fatal("Failed to write destination file:", err)
	}

	opts := TokenOptions{
		KeyAlgo:          tpm2.AlgRSA,
		VerifierEndpoint: mockAttestationServer.Server.URL,
		EventLog:         test.Cos85AmdSevEventLog,
	}

	token, err := RunToken(context.Background(), rwc, opts)
	if err != nil {
		t.Errorf("RunToken() failed with custom event log: %v", err)
	}
	if len(token) == 0 {
		t.Errorf("expected token output, got empty")
	}

	ExternalTPM = rwc
	t.Cleanup(func() {
		ExternalTPM = nil
		eventLog = defaultEventLog
		if f := tokenCmd.Flags().Lookup("event-log"); f != nil {
			f.Changed = false
			f.Value.Set(defaultEventLog)
		}
	})
	RootCmd.SetArgs([]string{"token", "--algo", algo, "--verifier-endpoint", mockAttestationServer.Server.URL, "--event-log", destPath})
	if err := RootCmd.Execute(); err != nil {
		t.Error(err)
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
	RootCmd.SetArgs([]string{"token", "--algo", "invalid-algo"})
	err := RootCmd.Execute()
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

	mockOauth2Server, err := util.NewMockOauth2Server()
	if err != nil {
		t.Error(err)
	}
	defer mockOauth2Server.Stop()

	google.Endpoint = oauth2.Endpoint{
		AuthURL:   mockOauth2Server.Server.URL + "/o/oauth2/auth",
		TokenURL:  mockOauth2Server.Server.URL + "/token",
		AuthStyle: oauth2.AuthStyleInParams,
	}

	mockAttestationServer, err := util.NewMockAttestationServer()
	if err != nil {
		t.Error(err)
	}
	defer mockAttestationServer.Stop()

	ExternalTPM = rwc
	defer func() { ExternalTPM = nil }()

	outPath := filepath.Join(t.TempDir(), "token.txt")
	RootCmd.SetArgs([]string{"token", "--verifier-endpoint", mockAttestationServer.Server.URL, "--output", outPath})
	if err := RootCmd.Execute(); err != nil {
		t.Fatalf("RootCmd.Execute() failed: %v", err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}
	if len(data) == 0 {
		t.Error("expected non-empty output file")
	}
}
