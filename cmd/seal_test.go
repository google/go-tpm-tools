package cmd

import (
	"bytes"
	"crypto/sha256"
	"os"
	"strconv"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

func makeTempFile(tb testing.TB, content []byte) string {
	tb.Helper()
	file, err := os.CreateTemp("", "gotpm_test_*.txt")
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
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	ExternalTPM = rwc

	operations := []struct {
		name        string
		algo        string
		sealPCRs    string
		certifyPCRs string
	}{
		{"RSASeal", "rsa", "", ""},
		{"ECCSeal", "ecc", "", ""},
		{"RSASealWithPCR", "rsa", "7", ""},
		{"ECCSealWithPCR", "ecc", "7", ""},
		{"RSACertifyWithPCR", "rsa", "", "7"},
		{"ECCCertifyWithPCR", "ecc", "", "7"},
		{"RSASealAndCertifyWithPCR", "rsa", "7,8", "1"},
		{"ECCSealAndCertifyWithPCR", "ecc", "7", "7,23"},
	}
	for _, op := range operations {
		t.Run(op.name, func(t *testing.T) {
			secretIn := []byte("Hello")
			secretFile1 := makeTempFile(t, secretIn)
			defer os.Remove(secretFile1)
			sealedFile := makeTempFile(t, nil)
			defer os.Remove(sealedFile)
			secretFile2 := makeTempFile(t, nil)
			defer os.Remove(secretFile2)

			sealArgs := []string{"seal", "--quiet", "--input", secretFile1, "--output", sealedFile}
			if op.sealPCRs != "" {
				sealArgs = append(sealArgs, "--pcrs", op.sealPCRs)
			}
			if op.algo != "" {
				sealArgs = append(sealArgs, "--algo", op.algo)
			}
			RootCmd.SetArgs(sealArgs)
			if err := RootCmd.Execute(); err != nil {
				t.Error(err)
			}
			pcrs = []int{} // "flush" pcrs value in last Execute() cmd

			unsealArgs := []string{"unseal", "--quiet", "--input", sealedFile, "--output", secretFile2}
			if op.certifyPCRs != "" {
				unsealArgs = append(unsealArgs, "--pcrs", op.certifyPCRs)
			}
			RootCmd.SetArgs(unsealArgs)
			if err := RootCmd.Execute(); err != nil {
				t.Error(err)
			}
			secretOut, err := os.ReadFile(secretFile2)
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
	rwc := test.GetTPM(t)
	defer client.CheckedClose(t, rwc)
	ExternalTPM = rwc
	extension := bytes.Repeat([]byte{0xAA}, sha256.Size)

	sealPCR := test.DebugPCR
	certPCR := test.ApplicationPCR
	operations := []struct {
		name        string
		sealPCRs    string
		certifyPCRs string
		pcrToExtend []int
	}{
		// TODO(joerichey): Add test that TPM2_Reset make unsealing fail
		{"ExtendPCRAndUnseal", strconv.Itoa(sealPCR), "", []int{sealPCR}},
		{"ExtendPCRAndCertify", strconv.Itoa(sealPCR), strconv.Itoa(certPCR), []int{certPCR}},
		{"ExtendPCRAndCertify2", "", strconv.Itoa(certPCR), []int{certPCR}},
	}
	for _, op := range operations {
		t.Run(op.name, func(t *testing.T) {
			secretIn := []byte("Hello")
			secretFile := makeTempFile(t, secretIn)
			defer os.Remove(secretFile)
			sealedFile := makeTempFile(t, nil)
			defer os.Remove(sealedFile)

			sealArgs := []string{"seal", "--quiet", "--input", secretFile, "--output", sealedFile}
			if op.sealPCRs != "" {
				sealArgs = append(sealArgs, "--pcrs", op.sealPCRs)
			}
			RootCmd.SetArgs(sealArgs)
			if err := RootCmd.Execute(); err != nil {
				t.Error(err)
			}
			pcrs = []int{} // "flush" pcrs value in last Execute() cmd

			for _, pcr := range op.pcrToExtend {
				pcrHandle := tpmutil.Handle(pcr)
				if err := tpm2.PCRExtend(rwc, pcrHandle, tpm2.AlgSHA256, extension, ""); err != nil {
					t.Fatal(err)
				}
			}

			unsealArgs := []string{"unseal", "--quiet", "--input", sealedFile, "--output", secretFile}
			if op.certifyPCRs != "" {
				unsealArgs = append(unsealArgs, "--pcrs", op.certifyPCRs)
			}
			RootCmd.SetArgs(unsealArgs)
			if RootCmd.Execute() == nil {
				t.Error("Unsealing should have failed")
			}
		})
	}
}
