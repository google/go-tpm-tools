package cmd

import (
	"bytes"
	"io"
	"os"
	"strconv"
	"testing"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)
var generateKey = map[string]func(rw io.ReadWriter) (*client.Key, error){
	"RSA": client.GceAttestationKeyRSA,
	"ECC": client.GceAttestationKeyECC,
}
var getIndex = map[string]uint32{
	"RSA": client.GceAKTemplateNVIndexRSA,
	"ECC": client.GceAKTemplateNVIndexECC,
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
			Point: tpm2.ECPoint{
				XRaw: []byte{231, 223, 129, 82, 74, 196, 103, 67, 32, 119, 206, 163, 207, 11, 118, 76, 52, 125, 98, 2, 162, 40, 24, 237, 189, 214, 161,
					209, 93, 215, 83, 97},
				YRaw: []byte{215, 25, 85, 187, 225, 17, 185, 91, 60, 173, 151, 178, 136, 21, 84, 56, 131, 125, 156, 50, 219, 68, 128,
					57, 236, 173, 217, 145, 25, 63, 112, 231},
			},
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
			ModulusRaw: []byte{240, 53, 205, 125, 1, 223, 48, 193, 34, 51, 180, 74, 245, 203, 239, 248, 235, 135, 119, 178, 102, 200, 62, 85, 151, 199,
				197, 222, 5, 148, 208, 254, 110, 208, 222, 116, 38, 61, 34, 125, 222, 152, 46, 10, 48, 146, 115, 194, 99, 67, 163, 101, 78, 255, 238, 144,
				98, 211, 172, 3, 115, 170, 200, 13, 91, 73, 137, 229, 166, 170, 25, 45, 249, 126, 193, 5, 200, 153, 152, 34, 131, 24, 155, 64, 208, 222,
				55, 145, 80, 103, 93, 136, 197, 48, 136, 47, 53, 127, 46, 116, 160, 186, 36, 133, 82, 128, 237, 54, 197, 139, 52, 68, 174, 92, 43, 34, 111,
				214, 56, 167, 46, 42, 249, 119, 62, 199, 39, 192, 116, 124, 6, 187, 0, 95, 243, 241, 77, 13, 183, 126, 145, 141, 35, 58, 35, 176, 239, 216,
				153, 208, 71, 104, 213, 32, 111, 44, 94, 154, 151, 124, 66, 72, 198, 75, 85, 50, 130, 18, 22, 96, 175, 127, 73, 227, 218, 185, 147, 128,
				117, 7, 139, 29, 202, 131, 16, 7, 67, 194, 190, 234, 139, 58, 179, 12, 115, 202, 80, 65, 186, 119, 91, 209, 161, 113, 175, 122, 96, 231,
				183, 230, 2, 12, 25, 175, 82, 136, 35, 37, 56, 0, 155, 64, 125, 197, 129, 143, 251, 140, 237, 213, 50, 116, 227, 15, 232, 183, 14, 7, 68,
				144, 41, 178, 114, 11, 107, 186, 56, 17, 224, 214, 84, 214, 50, 124, 103, 197},
		},
	}
}
func gceAttestationKey(tb testing.TB, rwc io.ReadWriteCloser, algo string, data []byte) (*client.Key, error) {
	var err error
	idx := tpmutil.Handle(getIndex[algo])
	if err := tpm2.NVDefineSpace(rwc, tpm2.HandlePlatform, idx,
		"", "", nil,
		tpm2.AttrPPWrite|tpm2.AttrPPRead|tpm2.AttrWriteDefine|tpm2.AttrOwnerRead|tpm2.AttrAuthRead|tpm2.AttrPlatformCreate|tpm2.AttrNoDA,
		uint16(len(data))); err != nil {
		tb.Fatalf("NVDefineSpace failed: %v", err)
	}
	defer tpm2.NVUndefineSpace(rwc, "", tpm2.HandlePlatform, idx)
	err = tpm2.NVWrite(rwc, tpm2.HandlePlatform, idx, "", data, 0)
	if err != nil {
		tb.Fatalf("failed to write NVIndex: %v", err)
	}
	createKey := generateKey[algo]
	k, err := createKey(rwc)
	if err != nil {
		tb.Fatalf("failed to open GCE AK: %v", err)
	}
	return k, nil
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
		name     string
		key      string
		algo     string
		nonce    string
		teenonce string
	}{
		{"DefaultKey", "", "rsa", "2222", ""},
		{"Withnonce", "AK", "ecc", "2222", ""},
	}
	for _, op := range tests {
		t.Run(op.name, func(t *testing.T) {
			secretFile1 := makeOutputFile(t, "attest.binarypb")
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
			if op.teenonce != "" {
				attestArgs = append(attestArgs, "--teenonce", op.teenonce)
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
		format_attest  string
		format_debug   string
	}{
		{"Format:binary", "abcd", inputFile, outputFile, "binarypb", "textproto"},
		{"Format:textproto", "abcd", inputFile, outputFile, "textproto", "binarypb"},
		{"Format:textproto", "abcd", inputFile, outputFile, "textproto", "xyz"},
	}
	for _, op := range tests {
		t.Run(op.name, func(t *testing.T) {
			attestArgs := []string{"attest", "--nonce", op.nonce, "--output", op.report, "--format", op.format_attest}
			RootCmd.SetArgs(attestArgs)
			if err := RootCmd.Execute(); err != nil {
				t.Error(err)
			}
			debugArgs := []string{"verify", "debug", "--nonce", op.nonce, "--input", op.report, "--output", op.verifiedReport, "--format", op.format_debug}
			RootCmd.SetArgs(debugArgs)
			if err := RootCmd.Execute(); err == nil {
				t.Error(err)
			}
		})
	}
}
func TestAttestWithGCEAK(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	ExternalTPM = rwc
	var template = map[string]tpm2.Public{
		"RSA": GCEAKTemplateRSA(),
		"ECC": GCEAKTemplateECC(),
	}
	tests := []struct {
		name    string
		nonce   []byte
		keyAlgo string
	}{
		{"gceAK:RSA", []byte{1, 2, 3, 4}, "RSA"},
		{"gceAK:ECC", []byte{1, 2, 3, 4}, "ECC"},
	}
	for _, op := range tests {
		t.Run(op.name, func(t *testing.T) {
			data, err := template[op.keyAlgo].Encode()
			if err != nil {
				t.Fatalf("failed to encode GCEAKTemplateRSA: %v", err)
			}
			k, err := gceAttestationKey(t, rwc, op.keyAlgo, data)
			if err != nil {
				t.Error(err)
			}
			defer k.Close()
			attestOpts := client.AttestOpts{}
			attestOpts.Nonce = op.nonce
			attestation, err := k.Attest(attestOpts)
			if err != nil {
				t.Error(err)
			}
			// Validate AK Pub.
			ak, err := gceAttestationKey(t, rwc, op.keyAlgo, data)
			if err != nil {
				t.Fatalf("failed to create gceAK: %v", err)
			}
			defer ak.Close()
			pubBytes, err := ak.PublicArea().Encode()
			if err != nil {
				t.Fatalf("failed to encode AK: %v", err)
			}
			if !bytes.Equal(attestation.GetAkPub(), pubBytes) {
				t.Errorf("Attestation AKPub did not match expected AK pub")
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
	t.Cleanup(mock.Stop)
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
	instanceId, err := strconv.ParseUint(dummyInstance.InstanceID, 10, 64)
	if err != nil {
		t.Error(err)
	}
	if instanceInfo.InstanceId != instanceId {
		t.Errorf("metadata.InstanceID() = %v, want %v", instanceInfo.InstanceId, instanceId)
	}
	if instanceInfo.Zone != dummyInstance.Zone {
		t.Errorf("metadata.Zone() = %v, want %v", instanceInfo.Zone, dummyInstance.Zone)
	}
}
func TestAttestTeeNonceFail(t *testing.T) {
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	ExternalTPM = rwc
	// non-nil TEENonce when TEEDevice is nil
	RootCmd.SetArgs([]string{"attest", "--nonce", "1234", "--key", "AK", "--teenonce", "12345678"})
	if err := RootCmd.Execute(); err == nil {
		t.Error("expected not-nil error")
	}
}


