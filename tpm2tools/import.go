package tpm2tools

import (
	"fmt"
	"io"

	tpmpb "github.com/google/go-tpm-tools/proto"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// Import decrypts the secret contained in an encoded import request.
// This method only works if the Key is a standard (low address) EK.
// The req parameter should come from server.CreateImportBlob.
func (k *Key) Import(rw io.ReadWriter, blob *tpmpb.ImportBlob) ([]byte, error) {
	session, _, err := tpm2.StartAuthSession(
		rw,
		tpm2.HandleNull,  /*tpmKey*/
		tpm2.HandleNull,  /*bindKey*/
		make([]byte, 16), /*nonceCaller*/
		nil,              /*secret*/
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext(rw, session)

	// Authorization w/ EK has to use Policy Secret sessions. Call
	// refreshSession, before each use of the EK using auth.
	refreshSession := func() error {
		nullAuth := tpm2.AuthCommand{Session: tpm2.HandlePasswordSession, Attributes: tpm2.AttrContinueSession}
		if _, err := tpm2.PolicySecret(rw, tpm2.HandleEndorsement, nullAuth, session, nil, nil, nil, 0); err != nil {
			return fmt.Errorf("authorizing policy failed: %s", err)
		}
		return nil
	}
	auth := tpm2.AuthCommand{Session: session, Attributes: tpm2.AttrContinueSession}

	if err = refreshSession(); err != nil {
		return nil, err
	}
	private, err := tpm2.Import(rw, k.Handle(), auth, blob.PublicArea, blob.Duplicate, blob.EncryptedSeed, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("import failed: %s", err)
	}

	if err = refreshSession(); err != nil {
		return nil, err
	}
	handle, _, err := tpm2.LoadUsingAuth(rw, k.Handle(), auth, blob.PublicArea, private)
	if err != nil {
		return nil, fmt.Errorf("load failed: %s", err)
	}
	defer tpm2.FlushContext(rw, handle)

	var out []byte
	//if blob.Pcrs == nil || len(blob.Pcrs.Pcrs) == 0 {
	if len(blob.Pcrs.GetPcrs()) == 0 {
		// The object to be imported does not have a PCR policy.
		out, err = tpm2.Unseal(rw, handle, "")
	} else {
		// The object to be imported has a PCR policy.
		pcrSel := PCRSelection(blob.Pcrs)

		var unsealSession tpmutil.Handle
		unsealSession, err = createPCRSession(rw, pcrSel)
		if err != nil {
			return nil, err
		}
		defer tpm2.FlushContext(rw, unsealSession)

		out, err = tpm2.UnsealWithSession(rw, unsealSession, handle, "")
	}
	if err != nil {
		return nil, fmt.Errorf("unseal failed: %s", err)
	}
	return out, nil
}
