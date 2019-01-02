package tpm2tools

import (
	"crypto"
	"crypto/rsa"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// Key wraps an active TPM2 key. Users of Key should be sure to call Close()
// when finished using the Key, so that the underlying TPM handle can be freed.
type Key struct {
	rw           io.ReadWriter
	handle       tpmutil.Handle
	pubArea      tpm2.Public
	pubKey       crypto.PublicKey
	creationData *tpm2.CreationData
	creationHash []byte
	ticket       *tpm2.Ticket
	name         tpm2.Name
}

// EndorsementKeyRSA generates and loads a key from DefaultEKTemplateRSA.
func EndorsementKeyRSA(rw io.ReadWriter) (*Key, error) {
	return NewKey(rw, tpm2.HandleEndorsement, DefaultEKTemplateRSA())
}

// EndorsementKeyFromNvIndex generates and loads an endorsement key using the
// template stored at the provided nvdata index. This is useful for TPMs which
// have a preinstalled AIK template.
func EndorsementKeyFromNvIndex(rw io.ReadWriter, idx uint32) (*Key, error) {
	data, err := tpm2.NVRead(rw, tpmutil.Handle(idx))
	if err != nil {
		return nil, fmt.Errorf("read error at index %d: %v", idx, err)
	}
	template, err := tpm2.DecodePublic(data)
	if err != nil {
		return nil, fmt.Errorf("index %d data was not a TPM key template: %v", idx, err)
	}
	return NewKey(rw, tpm2.HandleEndorsement, template)
}

// NewKey generates a key from the template and loads that key into the TPM
// under the specified parent. NewKey can call many different TPM commands:
//   - If parent is tpm2.Handle{Owner|Endorsement|Platform|Null} a primary key
//     is created in the specified hierarchy (using CreatePrimary).
//   - If parent is a valid key handle, a normal key object is created under
//     that parent (using Create and Load). NOTE: Not yet supported.
// This function also assumes that the desired key:
//   - Does not have its usage locked to specific PCR values
//   - Usable with empty authorization sessions (i.e. doesn't need a password)
func NewKey(rw io.ReadWriter, parent tpmutil.Handle, template tpm2.Public) (key *Key, err error) {
	key = &Key{rw: rw}
	var pubArea, creationData, name []byte

	if parent == tpm2.HandleOwner || parent == tpm2.HandleEndorsement ||
		parent == tpm2.HandlePlatform || parent == tpm2.HandleNull {
		key.handle, pubArea, creationData, key.creationHash, key.ticket, name, err =
			tpm2.CreatePrimaryEx(rw, parent, tpm2.PCRSelection{}, "", "", template)
		if err != nil {
			return
		}
	} else {
		// TODO add support for normal objects with Create() and Load()
		return nil, fmt.Errorf("unsupported parent handle: %x", parent)
	}

	// Prevent leaking the handle on failure
	defer func() {
		if err != nil {
			key.Close()
		}
	}()

	if key.pubArea, err = tpm2.DecodePublic(pubArea); err != nil {
		return
	}
	if key.pubArea.Type != tpm2.AlgRSA {
		return nil, fmt.Errorf("keys of type %v are not yet supported", key.pubArea.Type)
	}
	key.pubKey = &rsa.PublicKey{
		N: key.pubArea.RSAParameters.Modulus,
		E: int(key.pubArea.RSAParameters.Exponent),
	}
	if key.creationData, err = tpm2.DecodeCreationData(creationData); err != nil {
		return
	}

	key.name = tpm2.Name{Digest: &tpm2.HashValue{}}
	n, err := tpmutil.Unpack(name, &key.name.Digest.Alg)
	if err != nil {
		return
	}
	key.name.Digest.Value = name[n:]

	hashFn, err := key.name.Digest.Alg.HashConstructor()
	if err != nil {
		return
	}
	if hashFn().Size() != len(key.name.Digest.Value) {
		return nil, fmt.Errorf("expected name buffer of length %d, got %d",
			hashFn().Size(), len(key.name.Digest.Value))
	}
	return
}

// Handle allows this key to be used directly with other go-tpm commands.
func (k *Key) Handle() tpmutil.Handle {
	return k.handle
}

// Name is hash of this key's public area. Only the Digest field will ever be
// populated. It is useful for various TPM commands related to authorization.
func (k *Key) Name() tpm2.Name {
	return k.name
}

// PublicKey provides a go interface to the loaded key's public area.
func (k *Key) PublicKey() crypto.PublicKey {
	return k.pubKey
}

// Close should be called when the key is no longer needed. This is important to
// do as most TPMs can only have a small number of key simultaneously loaded.
func (k *Key) Close() {
	tpm2.FlushContext(k.rw, k.handle)
}
