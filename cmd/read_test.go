package cmd

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"testing"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// defineAndWriteNV defines an NV index with the given attributes, writes data
// to it using owner authorization, and undefines it at the end of the test.
func defineAndWriteNV(t *testing.T, rw io.ReadWriter, index tpmutil.Handle, attrs tpm2.NVAttr, data []byte) {
	t.Helper()
	if err := tpm2.NVDefineSpace(rw, tpm2.HandleOwner, index, "", "", nil, attrs, uint16(len(data))); err != nil {
		t.Fatalf("NVDefineSpace(%#x) returned error: %v", uint32(index), err)
	}
	t.Cleanup(func() {
		if err := tpm2.NVUndefineSpace(rw, "", tpm2.HandleOwner, index); err != nil {
			t.Errorf("NVUndefineSpace(%#x) returned error: %v", uint32(index), err)
		}
	})
	if err := tpm2.NVWrite(rw, tpm2.HandleOwner, index, "", data, 0); err != nil {
		t.Fatalf("NVWrite(%#x) returned error: %v", uint32(index), err)
	}
}

// TestNVReadAuthorization checks that gotpm picks a usable authorization
// handle for both OWNERREAD and AUTHREAD indexes. AUTHREAD-only indexes (used
// by, for example, Titan TPMs for the EK certificate) must be read with the
// index itself as the authorization handle; using the owner hierarchy fails
// with TPM_RC_NV_AUTHORIZATION.
func TestNVReadAuthorization(t *testing.T) {
	rwc := test.GetTPM(t)
	// Registered before the NV indexes are defined so that cleanup runs in the
	// reverse order: undefine the indexes first, then close the TPM.
	t.Cleanup(func() {
		ExternalTPM = nil
		client.CheckedClose(t, rwc)
	})
	ExternalTPM = rwc

	ownerReadIndex := tpmutil.Handle(0x01500000)
	authReadIndex := tpmutil.Handle(0x01500001)
	ownerReadData := []byte("owner readable")
	authReadData := []byte("index readable")

	defineAndWriteNV(t, rwc, ownerReadIndex, tpm2.AttrOwnerWrite|tpm2.AttrOwnerRead|tpm2.AttrNoDA, ownerReadData)
	defineAndWriteNV(t, rwc, authReadIndex, tpm2.AttrOwnerWrite|tpm2.AttrAuthRead|tpm2.AttrNoDA, authReadData)

	for _, tc := range []struct {
		name       string
		index      tpmutil.Handle
		authHandle string
		want       []byte
		wantErr    bool
	}{
		{name: "AutoOwnerRead", index: ownerReadIndex, authHandle: "auto", want: ownerReadData},
		{name: "AutoAuthRead", index: authReadIndex, authHandle: "auto", want: authReadData},
		{name: "ExplicitOwner", index: ownerReadIndex, authHandle: "owner", want: ownerReadData},
		{name: "ExplicitIndex", index: authReadIndex, authHandle: "index", want: authReadData},
		// Owner authorization is not permitted on an AUTHREAD-only index.
		{name: "OwnerAuthOnAuthReadIndex", index: authReadIndex, authHandle: "owner", wantErr: true},
		{name: "UnknownAuthHandle", index: ownerReadIndex, authHandle: "bogus", wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			outFile := makeTempFile(t, nil)
			defer os.Remove(outFile)

			RootCmd.SetArgs([]string{"read", "nvdata", "--quiet",
				"--index", fmt.Sprintf("%#x", uint32(tc.index)),
				"--auth-handle", tc.authHandle,
				"--output", outFile})
			err := RootCmd.Execute()
			if tc.wantErr {
				if err == nil {
					t.Fatal("read nvdata returned no error, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("read nvdata returned error: %v", err)
			}

			got, err := os.ReadFile(outFile)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tc.want) {
				t.Errorf("read nvdata = %q, want %q", got, tc.want)
			}
		})
	}
}
