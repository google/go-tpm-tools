package tpm2tools

import (
	"fmt"
	"io"

	tpmpb "github.com/google/go-tpm-tools/proto"
	"github.com/google/go-tpm/tpm2"
)

// Import decrypts the secret contained in an encoded import request.
// The key used must be an encryption key (signing keys cannot be used).
// The req parameter should come from server.CreateImportBlob.
func (k *Key) Import(rw io.ReadWriter, blob *tpmpb.ImportBlob) ([]byte, error) {
	auth, err := k.session.Auth()
	if err != nil {
		return nil, err
	}
	private, err := tpm2.Import(rw, k.Handle(), auth, blob.PublicArea, blob.Duplicate, blob.EncryptedSeed, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("import failed: %s", err)
	}

	auth, err = k.session.Auth()
	if err != nil {
		return nil, err
	}
	handle, _, err := tpm2.LoadUsingAuth(rw, k.Handle(), auth, blob.PublicArea, private)
	if err != nil {
		return nil, fmt.Errorf("load failed: %s", err)
	}
	defer tpm2.FlushContext(rw, handle)

	unsealSession, err := newPCRSession(rw, PCRSelection(blob.Pcrs))
	if err != nil {
		return nil, err
	}
	defer unsealSession.Close()

	auth, err = unsealSession.Auth()
	if err != nil {
		return nil, err
	}
	out, err := tpm2.UnsealWithSession(rw, auth.Session, handle, "")
	if err != nil {
		return nil, fmt.Errorf("unseal failed: %s", err)
	}
	return out, nil
}
