package tpm2tools

import (
	"crypto"
	"crypto/sha256"
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

// Seal will seal the sensitive data with the given SealingOPT.
// SealingOPT contains some PCRs values which will bind to the secret. Those PCRs
// will be used to generate a ticket to certify the seal.
// SealingOPT can be nil, in which case the secert will not be bind to any PCRs
func (k *Key) Seal(sensitive []byte, sOpt SealingOpt) (*proto.SealedBytes, error) {
	var auth []byte
	var pcrList []int32
	var certifyPCRs tpm2.PCRSelection
	var err error

	if sOpt == nil {
		certifyPCRs = tpm2.PCRSelection{}
		auth = nil
	} else {
		pcrs, err := sOpt.PCRsForSealing(k.rw)
		if err != nil {
			return nil, err
		}
		auth, err = computePCRSessionAuthFromPCRsProto(pcrs)
		if err != nil {
			return nil, err
		}
		for pcrNum := range pcrs.GetPcrs() {
			pcrList = append(pcrList, int32(pcrNum))
		}
		certifyPCRs = sOpt.GetPCRSelection()
	}
	sb, err := sealHelper(k.rw, k.Handle(), auth, sensitive, certifyPCRs)
	if err != nil {
		return nil, err
	}
	sb.Pcrs = pcrList

	sb.Hash = proto.HashAlgo_SHA256
	sb.Srk = proto.ObjectType(k.pubArea.Type)
	return sb, nil
}

func sealHelper(rw io.ReadWriter, parentHandle tpmutil.Handle, auth []byte, sensitive []byte, certifyPCRsSel tpm2.PCRSelection) (*proto.SealedBytes, error) {
	inPublic := tpm2.Public{
		Type:       tpm2.AlgKeyedHash,
		NameAlg:    tpm2.AlgSHA256,
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
		return nil, err
	}
	decodedCreationData, err := tpm2.DecodeCreationData(creationData)

	if err != nil {
		return nil, err
	}
	certifiedPCR, err := ReadPCRs(rw, certifyPCRsSel.PCRs, certifyPCRsSel.Hash)
	if err != nil {
		return nil, err
	}
	computedDigest, err := ComputePCRDigest(certifiedPCR, tpm2.AlgSHA256)

	// make sure PCR has not been changed after sealing
	if subtle.ConstantTimeCompare(computedDigest, decodedCreationData.PCRDigest) == 0 {
		return nil, fmt.Errorf("PCRs have been modified after sealing")
	}

	sb := proto.SealedBytes{}
	sb.CertifiedPcrs = certifiedPCR
	sb.Priv = priv
	sb.Pub = pub
	sb.CreationData = creationData

	t, err := tpmutil.Pack(ticket)
	if err != nil {
		return nil, err
	}
	sb.Ticket = t

	return &sb, nil
}

// Unseal takes a private/public pair of buffers and attempts to reverse the
// sealing process under the owner hierarchy using the SHA256 versions of the
// provided PCRs.
// CertificationOpt can be nil, which means no certify will be performed.
// The Key k is used as the parent key.
func (k *Key) Unseal(in *proto.SealedBytes, cOpt CertificationOpt) ([]byte, error) {
	if in.Srk != proto.ObjectType(k.pubArea.Type) {
		return nil, fmt.Errorf("Expected key of type %v, got %v", in.Srk, k.pubArea.Type)
	}
	if in.Hash != proto.HashAlgo_SHA256 {
		return nil, fmt.Errorf("Only SHA256 PCRs are currently supported")
	}
	var pcrs []int
	for _, pcr := range in.Pcrs {
		pcrs = append(pcrs, int(pcr))
	}
	session, err := createPCRSession(k.rw, pcrs)
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %v", err)
	}
	defer tpm2.FlushContext(k.rw, session)

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
		_, err = tpmutil.Unpack(in.GetTicket(), &ticket)
		if err != nil {
			return nil, fmt.Errorf("Ticket unpack failed: %v", err)
		}
		hashCon := sha256.New()
		hashCon.Write(in.GetCreationData())
		creationDataHash := hashCon.Sum(nil)
		_, _, err = tpm2.CertifyCreation(k.rw, "", sealed, tpm2.HandleNull, nil, creationDataHash, tpm2.SigScheme{}, ticket)
		if err != nil {
			return nil, fmt.Errorf("failed to certify creation: %v", err)
		}
		decodedCreation, err := tpm2.DecodeCreationData(in.GetCreationData())
		err = cOpt.CertifyPCRs(k.rw, decodedCreation.PCRDigest)
		if err != nil {
			return nil, fmt.Errorf("failed to certify PCRs: %v", err)
		}
	}
	// if sealing to 0 PCRs, then we don't need an auth session to unseal the data
	if len(pcrs) == 0 {
		return tpm2.Unseal(k.rw, sealed, "")
	}
	return tpm2.UnsealWithSession(k.rw, session, sealed, "")
}

// Reseal unwraps a secret and rewraps it under the auth value that would be
// produced by the PCR state in pcrs.
// The Key k is used as the parent key.
func (k *Key) Reseal(in *proto.SealedBytes, cOpt CertificationOpt, sOpt SealingOpt) (*proto.SealedBytes, error) {
	sensitive, err := k.Unseal(in, cOpt)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal: %v", err)
	}
	return k.Seal(sensitive, sOpt)
}

type tpmsPCRSelection struct {
	Hash tpm2.Algorithm
	Size byte
	PCRs tpmutil.RawBytes
}

type sessionSummary struct {
	OldDigest      tpmutil.RawBytes
	CmdIDPolicyPCR uint32
	NumPcrSels     uint32
	Sel            tpmsPCRSelection
	PcrDigest      tpmutil.RawBytes
}

func computePCRSessionAuthFromPCRsProto(pcrs *proto.Pcrs) ([]byte, error) {
	pcrsMap := make(map[int][]byte)
	for k, v := range pcrs.GetPcrs() {
		pcrsMap[int(k)] = v
	}
	return computePCRSessionAuth(pcrsMap)
}

func computePCRSessionAuth(pcrs map[int][]byte) ([]byte, error) {
	var pcrBits [3]byte
	for pcr := range pcrs {
		byteNum := pcr / 8
		bytePos := byte(1 << byte(pcr%8))
		pcrBits[byteNum] |= bytePos
	}
	pcrDigest := digestPCRList(pcrs)

	summary := sessionSummary{
		OldDigest:      make([]byte, sha256.Size),
		CmdIDPolicyPCR: uint32(tpm2.CmdPolicyPCR),
		NumPcrSels:     1,
		Sel: tpmsPCRSelection{
			Hash: tpm2.AlgSHA256,
			Size: 3,
			PCRs: pcrBits[:],
		},
		PcrDigest: pcrDigest,
	}
	b, err := tpmutil.Pack(summary)
	if err != nil {
		return nil, fmt.Errorf("failed to pack for hashing: %v ", err)
	}

	digest := sha256.Sum256(b)
	return digest[:], nil
}

func digestPCRList(pcrs map[int][]byte) []byte {
	hash := crypto.SHA256.New()
	for i := 0; i < 24; i++ {
		if pcrValue, exists := pcrs[i]; exists {
			hash.Write(pcrValue)
		}
	}
	return hash.Sum(nil)
}

func getPCRSessionAuth(rw io.ReadWriter, pcrs []int) ([]byte, error) {
	handle, err := createPCRSession(rw, pcrs)
	if err != nil {
		return nil, fmt.Errorf("failed to get digest: %v", err)
	}
	defer tpm2.FlushContext(rw, handle)

	digest, err := tpm2.PolicyGetDigest(rw, handle)
	if err != nil {
		return nil, fmt.Errorf("could not get digest from session: %v", err)
	}

	return digest, nil
}

func createPCRSession(rw io.ReadWriter, pcrs []int) (tpmutil.Handle, error) {
	nonceIn := make([]byte, 16)
	/* This session assumes the bus is trusted.  */
	handle, _, err := tpm2.StartAuthSession(
		rw,
		tpm2.HandleNull,
		tpm2.HandleNull,
		nonceIn,
		/*secret=*/ nil,
		tpm2.SessionPolicy,
		tpm2.AlgNull,
		tpm2.AlgSHA256)
	if err != nil {
		return tpm2.HandleNull, fmt.Errorf("failed to start auth session: %v", err)
	}

	// if pcrs is nil, then create a password session, otherwise create a policy PCRs session
	if pcrs == nil || len(pcrs) == 0 {
		if err = tpm2.PolicyPassword(rw, handle); err != nil {
			return tpm2.HandleNull, fmt.Errorf("auth step PolicyPassword failed: %v", err)
		}
	} else {
		sel := tpm2.PCRSelection{
			Hash: tpm2.AlgSHA256,
			PCRs: pcrs,
		}
		if err = tpm2.PolicyPCR(rw, handle, nil, sel); err != nil {
			return tpm2.HandleNull, fmt.Errorf("auth step PolicyPCR failed: %v", err)
		}
	}

	return handle, nil
}
