package tests

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

	"github.com/google/go-tpm-tools/gotpm/cmd"
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
	cmd.ExternalTPM = rwc

	tests := []struct {
		name   string
		pcrArg string
	}{
		{"Plain", ""},
		{"PCRs", "7,8"},
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
			if test.pcrArg != "" {
				sealArgs = append(sealArgs, "--pcrs", test.pcrArg)
			}
			cmd.RootCmd.SetArgs(sealArgs)
			if err := cmd.RootCmd.Execute(); err != nil {
				t.Error(err)
			}

			cmd.RootCmd.SetArgs([]string{"unseal", "--quiet", "--input", sealedFile, "--output", secretFile2})
			if err := cmd.RootCmd.Execute(); err != nil {
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
	cmd.ExternalTPM = rwc

	tests := []struct {
		name    string
		tpmFunc func(io.ReadWriter) error
	}{
		// TODO(joerichey): Add test that TPM2_Reset make unsealing fail
		{"ExtendPCR", func(rw io.ReadWriter) error {
			pcrToExtend := tpmutil.Handle(23)
			extension := bytes.Repeat([]byte{0xAA}, sha256.Size)
			return tpm2.PCRExtend(rw, pcrToExtend, tpm2.AlgSHA256, extension, "")
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			secretIn := []byte("Hello")
			secretFile := makeTempFile(t, secretIn)
			defer os.Remove(secretFile)
			sealedFile := makeTempFile(t, nil)
			defer os.Remove(sealedFile)

			cmd.RootCmd.SetArgs([]string{"seal", "--quiet", "--input", secretFile, "--output", sealedFile, "--pcrs", "23"})
			if err := cmd.RootCmd.Execute(); err != nil {
				t.Error(err)
			}

			if err := test.tpmFunc(rwc); err != nil {
				t.Fatal(err)
			}

			cmd.RootCmd.SetArgs([]string{"unseal", "--quiet", "--input", sealedFile, "--output", secretFile})
			if cmd.RootCmd.Execute() == nil {
				t.Error("Unsealing should have failed")
			}
		})
	}
}
