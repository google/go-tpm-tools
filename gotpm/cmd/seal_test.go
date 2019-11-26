package cmd

import (
	"bytes"
	"crypto/sha256"
	"io"
	"io/ioutil"
	"os"
	"testing"

	"github.com/google/go-tpm-tools/internal"
	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

func makeTempFile(tb testing.TB, content []byte) string {
	tb.Helper()
	file, err := ioutil.TempFile("", "gotpm_test_*.txt")
	if err != nil {
		tb.Fatal(err)
	}
	defer file.Close()
	if content != nil {
		if _, err := file.Write(content); err != nil {
			tb.Fatal(err)
		}
	}
	return file.Name()
}

func TestSealPlain(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer tpm2tools.CheckedClose(t, rwc)
	ExternalTPM = rwc

	tests := []struct {
		name        string
		algo        string
		sealPCRs    string
		certifyPCRs string
	}{
		{"RSA", "rsa", "", ""},
		{"ECC", "ecc", "", ""},
		{"RSAWithSealPCR", "rsa", "7", ""},
		{"ECCWithSealPCR", "ecc", "7", ""},
		{"RSAWithCertifyPCR", "rsa", "", "7"},
		{"ECCWithCertifyPCR", "ecc", "", "7"},
		{"RSAwithSealCertifyPCR", "rsa", "7,8", "1"},
		{"ECCwithSealCertifyPCR", "ecc", "7", "7,23"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			secretIn := []byte("Hello")
			secretFile1 := makeTempFile(t, secretIn)
			defer os.Remove(secretFile1)
			sealedFile := makeTempFile(t, nil)
			defer os.Remove(sealedFile)
			secretFile2 := makeTempFile(t, nil)
			defer os.Remove(secretFile2)

			sealArgs := []string{"seal", "--quiet", "--input", secretFile1, "--output", sealedFile}
			if test.sealPCRs != "" {
				sealArgs = append(sealArgs, "--pcrs", test.sealPCRs)
			}
			if test.algo != "" {
				sealArgs = append(sealArgs, "--algo", test.algo)
			}
			RootCmd.SetArgs(sealArgs)
			if err := RootCmd.Execute(); err != nil {
				t.Error(err)
			}
			initPCRs()

			unsealArgs := []string{"unseal", "--quiet", "--input", sealedFile, "--output", secretFile2}
			if test.certifyPCRs != "" {
				unsealArgs = append(unsealArgs, "--certify-pcrs", test.certifyPCRs)
			}
			RootCmd.SetArgs(unsealArgs)
			if err := RootCmd.Execute(); err != nil {
				t.Error(err)
			}
			secretOut, err := ioutil.ReadFile(secretFile2)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(secretIn, secretOut) {
				t.Errorf("Expected %s, got %s", secretIn, secretOut)
			}
		})
	}
}

func TestUnsealFail(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer tpm2tools.CheckedClose(t, rwc)
	ExternalTPM = rwc
	extendPCR := func(rw io.ReadWriter, pcr int) error {
		pcrToExtend := tpmutil.Handle(pcr)
		extension := bytes.Repeat([]byte{0xAA}, sha256.Size)
		return tpm2.PCRExtend(rw, pcrToExtend, tpm2.AlgSHA256, extension, "")
	}

	tests := []struct {
		name             string
		sealPCRs         string
		certifyPCRs      string
		tpmFunc          func(io.ReadWriter, int) error
		tpmFuncParameter int
	}{
		// TODO(joerichey): Add test that TPM2_Reset make unsealing fail
		{"ExtendSealPCR", "23", "", extendPCR, 23},
		{"ExtendCertifyPCR", "23", "7", extendPCR, 7},
		{"ExtendCertifyPCRWithNoSealPCR", "", "5", extendPCR, 5},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			secretIn := []byte("Hello")
			secretFile := makeTempFile(t, secretIn)
			defer os.Remove(secretFile)
			sealedFile := makeTempFile(t, nil)
			defer os.Remove(sealedFile)

			sealArgs := []string{"seal", "--quiet", "--input", secretFile, "--output", sealedFile}
			if test.sealPCRs != "" {
				sealArgs = append(sealArgs, "--pcrs", test.sealPCRs)
			}
			RootCmd.SetArgs(sealArgs)
			if err := RootCmd.Execute(); err != nil {
				t.Error(err)
			}
			initPCRs()

			if err := test.tpmFunc(rwc, test.tpmFuncParameter); err != nil {
				t.Fatal(err)
			}
			unsealArgs := []string{"unseal", "--quiet", "--input", sealedFile, "--output", secretFile}
			if test.certifyPCRs != "" {
				unsealArgs = append(unsealArgs, "--certify-pcrs", test.certifyPCRs)
			}

			RootCmd.SetArgs(unsealArgs)
			if err := RootCmd.Execute(); err == nil {
				t.Error("Unsealing should have failed")
			}
		})
	}
}
