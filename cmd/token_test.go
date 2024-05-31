package cmd

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	"github.com/google/go-tpm-tools/verifier/util"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

func TestTokenWithGCEAK(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	ExternalTPM = rwc
	secretFile1 := makeOutputFile(t, "token")
	defer os.RemoveAll(secretFile1)
	var template = map[string]tpm2.Public{
		"rsa": GCEAKTemplateRSA(),
		"ecc": GCEAKTemplateECC(),
	}
	tests := []struct {
		name string
		algo string
		fail bool
	}{
		{"gceAK:RSA", "rsa", true},
		{"gceAK:RSA", "rsa", false},
		{"gceAK:ECC", "ecc", false},
	}
	for _, op := range tests {
		t.Run(op.name, func(t *testing.T) {
			gceAkTemplate, err := template[op.algo].Encode()
			if err != nil {
				t.Fatalf("failed to encode GCEAKTemplateRSA: %v", err)
			}
			err = setGCEAKCertTemplate(t, rwc, op.algo, gceAkTemplate)
			if err != nil {
				t.Error(err)
			}
			defer tpm2.NVUndefineSpace(rwc, "", tpm2.HandlePlatform, tpmutil.Handle(getIndex[op.algo]))
			defer tpm2.NVUndefineSpace(rwc, "", tpm2.HandlePlatform, tpmutil.Handle(getCertIndex[op.algo]))

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

			mockCloudLoggingServerAddress, err = newMockCloudLoggingServer()
			if err != nil {
				t.Error(err)
			}

			if op.fail {
				RootCmd.SetArgs([]string{"token", "--algo", op.algo, "--output", secretFile1, "--verifier-endpoint", mockAttestationServer.Server.URL, "--cloud-log", "--audience", util.FakeCustomAudience, "--custom-nonce", "fail test"})
				if err := RootCmd.Execute(); err != nil && !strings.Contains(err.Error(), "googleapi: Error 400") {
					t.Error(err)
				}
			} else {
				RootCmd.SetArgs([]string{"token", "--algo", op.algo, "--output", secretFile1, "--verifier-endpoint", mockAttestationServer.Server.URL, "--cloud-log", "--audience", util.FakeCustomAudience, "--custom-nonce", util.FakeCustomNonce[0], "--custom-nonce", util.FakeCustomNonce[1]})
				if err := RootCmd.Execute(); err != nil {
					t.Error(err)
				}
			}
			// reset custom-nonce
			customNonce = nil
		})
	}
}

func TestCopiedCustomEventLogFile(t *testing.T) {
	if os.Getenv("RUN_TestCopiedCustomEventLogFile") != "true" {
		t.Skip("Skipping test: run this test manually with `go test -c -v ./cmd/...` and `sudo RUN_TestCopiedCustomEventLogFile=true ./cmd.test -test.run TestCopiedCustomEventLogFile`")
	}

	ExternalTPM = nil
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
	srcPath := "/sys/kernel/security/tpm0/binary_bios_measurements"
	destPath := filepath.Join(tmpDir, "copied_binary_bios_measurements")

	// Read the contents of the source file
	data, err := os.ReadFile(srcPath)
	if err != nil {
		t.Fatal("Failed to read source file:", err)
	}

	// Write the contents to the destination file
	err = os.WriteFile(destPath, data, 0644)
	if err != nil {
		t.Fatal("Failed to write destination file:", err)
	}

	RootCmd.SetArgs([]string{"token", "--verifier-endpoint", mockAttestationServer.Server.URL, "--event-log", destPath})
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
	// create self-signed Root CA
	ca, caKey := getTestCert(tb, nil, nil, nil)
	// sign the attestation key certificate
	akCert, _ := getTestCert(tb, attestKey.PublicKey(), ca, caKey)
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

// Returns an x509 Certificate for the provided pubkey, signed with the provided parent certificate and key.
// If the provided fields are nil, will create a self-signed certificate.
func getTestCert(tb testing.TB, pubKey crypto.PublicKey, parentCert *x509.Certificate, parentKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey) {
	certKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now(),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}

	if pubKey == nil && parentCert == nil && parentKey == nil {
		pubKey = certKey.Public()
		parentCert = template
		parentKey = certKey
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, template, parentCert, pubKey, parentKey)
	if err != nil {
		tb.Fatalf("Unable to create test certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		tb.Fatalf("Unable to parse test certificate: %v", err)
	}

	return cert, certKey
}
