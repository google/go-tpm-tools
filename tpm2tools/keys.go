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
	name         *tpm2.HashValue
}

// EndorsementKeyRSA returns the key created from DefaultEKTemplateRSA.
func EndorsementKeyRSA(rw io.ReadWriter) (*Key, error) {
	return EndorsementKeyFromTemplate(rw, DefaultEKTemplateRSA())
}

// EndorsementKeyFromNvIndex loads an endorsement key using the template
// stored at the provided nvdata index. This is usefull for TPMs which have a
// preinstalled AIK template.
func EndorsementKeyFromNvIndex(rw io.ReadWriter, idx uint32) (*Key, error) {
	data, err := tpm2.NVRead(rw, tpmutil.Handle(idx))
	if err != nil {
		return nil, fmt.Errorf("read error at index %d: %v", idx, err)
	}
	template, err := tpm2.DecodePublic(data)
	if err != nil {
		return nil, fmt.Errorf("index %d data was not a TPM key template: %v", idx, err)
	}
	return EndorsementKeyFromTemplate(rw, template)
}

// EndorsementKeyFromTemplate loads a primary key in the endorsement hierarchy
// using the provided template. This function assumes that the desired key:
//   - Does not have its usage locked to specific PCR values
//   - Usable with empty authorization sessions (i.e. doesn't need a password)
func EndorsementKeyFromTemplate(rw io.ReadWriter, template tpm2.Public) (*Key, error) {
	return newPrimaryKey(rw, tpm2.HandleEndorsement, template)
}

// StorageKeyFromTemplate loads a primary key in the owner hierarchy
// using the provided template. This function assumes that the desired key:
//   - Does not have its usage locked to specific PCR values
//   - Usable with empty authorization sessions (i.e. doesn't need a password)
func StorageKeyFromTemplate(rw io.ReadWriter, template tpm2.Public) (*Key, error) {
	return newPrimaryKey(rw, tpm2.HandleOwner, template)
}

// Wrapper around CreatePrimary used to load a key which does not need to be
// locked to any PCRs or use any authorization sessions.
func newPrimaryKey(rw io.ReadWriter, owner tpmutil.Handle, template tpm2.Public) (*Key, error) {
	key := &Key{rw: rw}

	var err error
	var pubArea, creationData, name []byte
	key.handle, pubArea, creationData, key.creationHash, key.ticket, name, err =
		tpm2.CreatePrimaryEx(rw, owner, tpm2.PCRSelection{}, "", "", template)
	if err != nil {
		return nil, err
	}

	if key.pubArea, err = tpm2.DecodePublic(pubArea); err != nil {
		return nil, err
	}
	if key.pubArea.Type != tpm2.AlgRSA {
		return nil, fmt.Errorf("Keys of type %v are not yet supported", key.pubArea.Type)
	}
	key.pubKey = &rsa.PublicKey{
		N: key.pubArea.RSAParameters.Modulus,
		E: int(key.pubArea.RSAParameters.Exponent),
	}
	if key.creationData, err = tpm2.DecodeCreationData(creationData); err != nil {
		return nil, err
	}

	key.name = &tpm2.HashValue{}
	n, err := tpmutil.Unpack(name, &key.name.Alg)
	if err != nil {
		return nil, err
	}
	key.name.Value = name[n:]

	hashFn, err := key.name.Alg.HashConstructor()
	if err != nil {
		return nil, err
	}
	if hashFn().Size() != len(key.name.Value) {
		return nil, fmt.Errorf("expected name buffer of length %d, got %d", hashFn().Size(), len(key.name.Value))
	}

	return key, nil
}

// Handle allows this key to be used directly with other go-tpm commands.
func (k *Key) Handle() tpmutil.Handle {
	return k.handle
}

// Name is hash of this key's public area. It is useful for various TPM
// commands related to authorization.
func (k *Key) Name() *tpm2.HashValue {
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
