package tpm2tools

import (
	"crypto"
	"crypto/subtle"
	"fmt"
	"io"

	"github.com/google/go-tpm-tools/proto"
	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

// Key wraps an active TPM2 key. Users of Key should be sure to call Close()
// when finished using the Key, so that the underlying TPM handle can be freed.
type Key struct {
	rw      io.ReadWriter
	handle  tpmutil.Handle
	pubArea tpm2.Public
	pubKey  crypto.PublicKey
	name    tpm2.Name
}

// EndorsementKeyRSA generates and loads a key from DefaultEKTemplateRSA.
func EndorsementKeyRSA(rw io.ReadWriter) (*Key, error) {
	return NewCachedKey(rw, tpm2.HandleEndorsement, DefaultEKTemplateRSA(), EKReservedHandle)
}

// EndorsementKeyECC generates and loads a key from DefaultEKTemplateECC.
func EndorsementKeyECC(rw io.ReadWriter) (*Key, error) {
	return NewKey(rw, tpm2.HandleEndorsement, DefaultEKTemplateECC())
}

// StorageRootKeyRSA generates and loads a key from SRKTemplateRSA.
func StorageRootKeyRSA(rw io.ReadWriter) (*Key, error) {
	return NewCachedKey(rw, tpm2.HandleOwner, SRKTemplateRSA(), SRKReservedHandle)
}

// AttestationIdentityKeyRSA generates and loads a key from AIKTemplateRSA
func AttestationIdentityKeyRSA(rw io.ReadWriter, nonces []byte) (*Key, error) {
	return NewKey(rw, tpm2.HandleOwner, AIKTemplateRSA(nonces))
}

// StorageRootKeyECC generates and loads a key from SRKTemplateECC.
func StorageRootKeyECC(rw io.ReadWriter) (*Key, error) {
	return NewKey(rw, tpm2.HandleOwner, SRKTemplateECC())
}

// EndorsementKeyFromNvIndex generates and loads an endorsement key using the
// template stored at the provided nvdata index. This is useful for TPMs which
// have a preinstalled AIK template.
func EndorsementKeyFromNvIndex(rw io.ReadWriter, idx uint32) (*Key, error) {
	return KeyFromNvIndex(rw, tpm2.HandleEndorsement, idx)
}

// KeyFromNvIndex generates and loads a key under the provided parent
// (possibly a hierarchy root tpm2.Handle{Owner|Endorsement|Platform|Null})
// using the template stored at the provided nvdata index.
func KeyFromNvIndex(rw io.ReadWriter, parent tpmutil.Handle, idx uint32) (*Key, error) {
	data, err := tpm2.NVRead(rw, tpmutil.Handle(idx))
	if err != nil {
		return nil, fmt.Errorf("read error at index %d: %v", idx, err)
	}
	template, err := tpm2.DecodePublic(data)
	if err != nil {
		return nil, fmt.Errorf("index %d data was not a TPM key template: %v", idx, err)
	}
	return NewKey(rw, parent, template)
}

// NewCachedKey is almost identical to NewKey, except that it initially tries to
// see if the a key matching the provided template is at cachedHandle. If so,
// that key is returned. If not, the key is created as in NewKey, and that key
// is persisted to the cachedHandle, overwriting any existing key there.
func NewCachedKey(rw io.ReadWriter, parent tpmutil.Handle, template tpm2.Public, cachedHandle tpmutil.Handle) (k *Key, err error) {
	owner := tpm2.HandleOwner
	if parent == tpm2.HandlePlatform {
		owner = tpm2.HandlePlatform
	} else if parent == tpm2.HandleNull {
		return nil, fmt.Errorf("Cannot cache objects in the null hierarchy")
	}

	cachedPub, _, _, err := tpm2.ReadPublic(rw, cachedHandle)
	if err == nil {
		if cachedPub.MatchesTemplate(template) {
			k = &Key{rw: rw, handle: cachedHandle, pubArea: cachedPub}
			return k, k.finish()
		}
		// Kick out old cached key if it does not match
		if err = tpm2.EvictControl(rw, "", owner, cachedHandle, cachedHandle); err != nil {
			return nil, err
		}
	}

	k, err = NewKey(rw, parent, template)
	if err != nil {
		return nil, err
	}
	defer tpm2.FlushContext(rw, k.handle)

	if err = tpm2.EvictControl(rw, "", owner, k.handle, cachedHandle); err != nil {
		return nil, err
	}
	k.handle = cachedHandle
	return k, nil
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
func NewKey(rw io.ReadWriter, parent tpmutil.Handle, template tpm2.Public) (k *Key, err error) {
	if !isHierarchy(parent) {
		// TODO add support for normal objects with Create() and Load()
		return nil, fmt.Errorf("unsupported parent handle: %x", parent)
	}

	handle, pubArea, _, _, _, _, err :=
		tpm2.CreatePrimaryEx(rw, parent, tpm2.PCRSelection{}, "", "", template)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			tpm2.FlushContext(rw, handle)
		}
	}()

	k = &Key{rw: rw, handle: handle}
	if k.pubArea, err = tpm2.DecodePublic(pubArea); err != nil {
		return
	}
	return k, k.finish()
}

func (k *Key) finish() error {
	var err error
	if k.pubKey, err = k.pubArea.Key(); err != nil {
		return err
	}
	k.name, err = k.pubArea.Name()
	return err
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

// Seal seals the sensitive byte buffer to the PCRs specified by SealingOpt (the
// SealingOpt cannot be nil). The sealing is done under Owner Hierarchy. During
// the sealing process, certification data will be created allowing Unseal() to
// validate the state of the TPM during the sealing process.
func (k *Key) Seal(sensitive []byte, sOpt SealingOpt) (*proto.SealedBytes, error) {
	if sOpt == nil {
		panic("Cannot seal to nil SealingOpt")
	}
	pcrs, err := sOpt.PCRsForSealing(k.rw)
	if err != nil {
		return nil, err
	}
	auth := ComputePCRSessionAuth(pcrs)
	sb, err := sealHelper(k.rw, k.Handle(), auth, sensitive, FullPcrSel(tpm2.Algorithm(pcrs.GetHash())))
	if err != nil {
		return nil, err
	}

	for pcrNum := range pcrs.GetPcrs() {
		sb.Pcrs = append(sb.Pcrs, int32(pcrNum))
	}
	sb.Hash = pcrs.GetHash()
	sb.Srk = proto.ObjectType(k.pubArea.Type)
	return sb, nil
}

func sealHelper(rw io.ReadWriter, parentHandle tpmutil.Handle, auth []byte, sensitive []byte, certifyPCRsSel tpm2.PCRSelection) (*proto.SealedBytes, error) {
	inPublic := tpm2.Public{
		Type:       tpm2.AlgKeyedHash,
		NameAlg:    sessionHashAlgTpm,
		Attributes: tpm2.FlagFixedTPM | tpm2.FlagFixedParent,
		AuthPolicy: auth,
	}
	if auth == nil {
		inPublic.Attributes |= tpm2.FlagUserWithAuth
	} else {
		inPublic.Attributes |= tpm2.FlagAdminWithPolicy
	}

	priv, pub, creationData, _, ticket, err := tpm2.CreateKeyWithSensitive(rw, parentHandle, certifyPCRsSel, "", "", inPublic, sensitive)
	if err != nil {
		return nil, fmt.Errorf("Failed to create key: %v", err)
	}
	certifiedPCR, err := ReadPCRs(rw, certifyPCRsSel)
	if err != nil {
		return nil, fmt.Errorf("Failed to read PCRs: %v", err)
	}
	computedDigest := computePCRDigest(certifiedPCR)

	decodedCreationData, err := tpm2.DecodeCreationData(creationData)
	if err != nil {
		return nil, fmt.Errorf("Failed to decode creation data: %v", err)
	}

	// make sure PCRs haven't being altered after sealing
	if subtle.ConstantTimeCompare(computedDigest, decodedCreationData.PCRDigest) == 0 {
		return nil, fmt.Errorf("PCRs have been modified after sealing")
	}

	sb := proto.SealedBytes{}
	sb.CertifiedPcrs = certifiedPCR
	sb.Priv = priv
	sb.Pub = pub
	sb.CreationData = creationData
	if sb.Ticket, err = tpmutil.Pack(ticket); err != nil {
		return nil, err
	}
	return &sb, nil
}

// Unseal attempts to reverse the process of Seal(), using the PCRs, public, and
// private data in proto.SealedBytes. Optionally, a CertificationOpt can be
// passed, to verify the state of the TPM when the data was sealed. A nil value
// can be passed to skip certification.
func (k *Key) Unseal(in *proto.SealedBytes, cOpt CertificationOpt) ([]byte, error) {
	if in.Srk != proto.ObjectType(k.pubArea.Type) {
		return nil, fmt.Errorf("Expected key of type %v, got %v", in.Srk, k.pubArea.Type)
	}
	sealed, _, err := tpm2.Load(
		k.rw,
		k.Handle(),
		/*parentPassword=*/ "",
		in.Pub,
		in.Priv)
	if err != nil {
		return nil, fmt.Errorf("failed to load sealed object: %v", err)
	}
	defer tpm2.FlushContext(k.rw, sealed)

	if cOpt != nil {
		var ticket tpm2.Ticket
		if _, err = tpmutil.Unpack(in.GetTicket(), &ticket); err != nil {
			return nil, fmt.Errorf("Ticket unpack failed: %v", err)
		}
		creationHash := sessionHashAlg.New()
		creationHash.Write(in.GetCreationData())
		if _, _, err = tpm2.CertifyCreation(k.rw, "", sealed, tpm2.HandleNull, nil, creationHash.Sum(nil), tpm2.SigScheme{}, ticket); err != nil {
			return nil, fmt.Errorf("failed to certify creation: %v", err)
		}
		if err := cOpt.CertifyPCRs(k.rw, in.GetCertifiedPcrs()); err != nil {
			return nil, fmt.Errorf("failed to certify PCRs: %v", err)
		}
	}

	sel := tpm2.PCRSelection{Hash: tpm2.Algorithm(in.Hash)}
	for _, pcr := range in.Pcrs {
		sel.PCRs = append(sel.PCRs, int(pcr))
	}
	session, err := createPCRSession(k.rw, sel)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %v", err)
	}
	defer tpm2.FlushContext(k.rw, session)

	return tpm2.UnsealWithSession(k.rw, session, sealed, "")
}

// Reseal is a shortcut to call Unseal() followed by Seal().
// CertificationOpt will be used in Unseal(), and SealingOpt wil be used in Seal()
func (k *Key) Reseal(in *proto.SealedBytes, cOpt CertificationOpt, sOpt SealingOpt) (*proto.SealedBytes, error) {
	sensitive, err := k.Unseal(in, cOpt)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal: %v", err)
	}
	return k.Seal(sensitive, sOpt)
}
