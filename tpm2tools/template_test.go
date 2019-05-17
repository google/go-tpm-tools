package tpm2tools

import (
	"crypto/sha256"
	"encoding/binary"
	"io"
	"testing"

	"github.com/google/go-tpm/tpmutil"

	"github.com/google/go-tpm-tools/internal"
	"github.com/google/go-tpm/tpm2"
)

func TestPolicyTemplate(t *testing.T) {
	rwc := internal.GetTPM(t)
	defer rwc.Close()

	// This is just an empty/default session for appling policies
	session, _, err := tpm2.StartAuthSession(
		rwc,
		tpm2.HandleNull,
		tpm2.HandleNull,
		make([]byte, 16),
		/*secret=*/ nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		t.Fatalf("Failed to start auth session: %v", err)
	}
	defer tpm2.FlushContext(rwc, session)

	childTemplate := DefaultEKTemplateRSA()
	childTemplateBytes, err := childTemplate.Encode()
	if err != nil {
		t.Fatalf("Failed to encode child template: %v", err)
	}

	childTemplateDigest := sha256.Sum256(childTemplateBytes)
	if err := tpm2.PolicyTemplate(rwc, session, childTemplateDigest[:]); err != nil {
		t.Fatalf("Failed to call PolicyTemplate: %v", err)
	}

	parentTemplate := DefaultEKTemplateRSA()
	parentTemplate.AuthPolicy = computeTemplateSessionAuth(childTemplateDigest[:])
	parent, err := NewKey(rwc, tpm2.HandleEndorsement, parentTemplate)
	if err != nil {
		t.Fatalf("Failed to create parent key: %v", err)
	}
	defer parent.Close()

	if err := createWithSessionAuth(rwc, parent, session, childTemplate); err != nil {
		t.Fatalf("Failed to create child key: %v", err)
	}
}

func computeTemplateSessionAuth(digest []byte) []byte {
	hash := sha256.New()

	hash.Write(make([]byte, sha256.Size))
	binary.Write(hash, binary.BigEndian, tpm2.CmdPolicyTemplate)
	hash.Write(digest)

	return hash.Sum(nil)
}

func createWithSessionAuth(rw io.ReadWriter, parent *Key, session tpmutil.Handle, childTemplate tpm2.Public) error {
	// authBuf, err := tpmutil.Pack(tpm2.AuthCommand{Session: session, Attributes: tpm2.AttrContinueSession})
	// if err != nil {
	// 	return fmt.Errorf("encoding authorization buffer: %v", err)
	// }

	// resp, code, err := tpmutil.RunCommand(
	// 	rw, tpm2.TagSessions, tpm2.CmdCreate,
	// 	parent.Handle(),
	// 	uint32(len(authBuf)), tpmutil.RawBytes(authBuf),
	// 	make([]byte, 4), // Empty sensitive area
	// 	childTemplate,
	// 	[]byte(nil),     // Empty outside info
	// 	uint32(0),       // Empty PCR list
	// )
	// if err != nil {
	// 	return err
	// }
	// if code != tpmutil.RCSuccess {
	// 	return fmt.Errorf("response status 0x%x", code)
	// }

	// var childHandle tpmutil.Handle
	// if _, err := tpmutil.Unpack(resp, &childHandle); err != nil {
	// 	return fmt.Errorf("decoding handle: %v", err)
	// }

	// return tpm2.FlushContext(rw, childHandle)

	handle, _, _, _, _, _, err := tpm2.CreateWithSession(rw, parent.Handle(), session, childTemplate)
	if err != nil {
		return err
	}
	return tpm2.FlushContext(rw, handle)
}
