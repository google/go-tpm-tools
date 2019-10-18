package tpm2tools

import (
	"fmt"
	"io"

	tpmpb "github.com/google/go-tpm-tools/proto"
	"github.com/google/go-tpm/tpm2"
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

	if blob.Pcrs == nil {
		// The object to be imported does not have a PCR policy.
		return tpm2.Unseal(rw, handle, "")
	} else {
		// The object to be imported has a PCR policy.
		unsealSession, _, err := tpm2.StartAuthSession(
			rw,
			tpm2.HandleNull,
			tpm2.HandleNull,
			make([]byte, 16),
			nil,
			tpm2.SessionPolicy,
			tpm2.AlgNull,
			tpm2.AlgSHA256)
		if err != nil {
			return nil, err
		}
		defer tpm2.FlushContext(rw, unsealSession)

		var pcrs []int
		for pcr := range blob.Pcrs.Pcrs {
			pcrs = append(pcrs, int(pcr))
		}
		var hash tpm2.Algorithm
		switch blob.Pcrs.Hash {
		case proto.HashAlgo_SHA1:
			hash = tpm2.AlgSHA1
		case proto.HashAlgo_SHA256:
			hash = tpm2.AlgSHA256
		default:
			return nil, fmt.Errorf("invalid hash algorithm: %v", blob.Pcrs.Hash)
		}
		if err = tpm2.PolicyPCR(rw, unsealSession, nil, tpm2.PCRSelection{hash, pcrs}); err != nil {
			return nil, err
		}
		return tpm2.UnsealWithSession(rw, unsealSession, handle, "")
	}
}
