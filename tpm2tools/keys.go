package tpm2tools

import (
	"crypto"
	"crypto/sha256"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
	"github.com/google/go-tpm/tpmutil"

	"github.com/google/go-tpm-tools/proto"
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
	return NewKey(rw, tpm2.HandleEndorsement, DefaultEKTemplateRSA())
}

// StorageRootKeyRSA generates and loads a key from SRKTemplateRSA.
func StorageRootKeyRSA(rw io.ReadWriter) (*Key, error) {
	return NewKey(rw, tpm2.HandleOwner, SRKTemplateRSA())
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
	if parent != tpm2.HandleOwner && parent != tpm2.HandleEndorsement &&
		parent != tpm2.HandlePlatform && parent != tpm2.HandleNull {
		// TODO add support for normal objects with Create() and Load()
		err = fmt.Errorf("unsupported parent handle: %x", parent)
		return
	}

	handle, pubArea, _, _, _, _, err :=
		tpm2.CreatePrimaryEx(rw, parent, tpm2.PCRSelection{}, "", "", template)
	if err != nil {
		return
	}

	key = &Key{rw: rw, handle: handle}
	// Do not leak the key, only use bare returns in this function.
	defer func() {
		if key != nil && err != nil {
			key.Close()
			key = nil
		}
	}()

	if key.pubArea, err = tpm2.DecodePublic(pubArea); err != nil {
		return
	}
	if key.pubKey, err = key.pubArea.Key(); err != nil {
		return
	}
	if key.name, err = key.pubArea.Name(); err != nil {
		return
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

// Seal seals the sensitive byte buffer to the provided PCRs under the owner
// hierarchy using the SHA256 versions of the provided PCRs.
// The Key k is used as the parent key.
func (k *Key) Seal(pcrs []int, sensitive []byte) (*proto.SealedBytes, error) {
	auth, err := getPCRSessionAuth(k.rw, pcrs)
	if err != nil {
		return nil, fmt.Errorf("could not get pcr session auth: %v", err)
	}

	sb, err := sealHelper(k.rw, k.Handle(), auth, sensitive)
	if err != nil {
		return nil, err
	}
	for _, pcr := range pcrs {
		sb.Pcrs = append(sb.Pcrs, int32(pcr))
	}
	sb.Hash = proto.HashAlgo_SHA256
	sb.Srk = proto.ObjectType(k.pubArea.Type)
	return sb, nil
}

func sealHelper(rw io.ReadWriter, parentHandle tpmutil.Handle, auth []byte, sensitive []byte) (*proto.SealedBytes, error) {
	priv, pub, err := tpm2.Seal(rw, parentHandle, "", "", auth, sensitive)
	if err != nil {
		return nil, fmt.Errorf("failed to seal data: %v", err)
	}

	sb := proto.SealedBytes{}
	sb.Priv = priv
	sb.Pub = pub
	return &sb, nil
}

// Unseal takes a private/public pair of buffers and attempts to reverse the
// sealing process under the owner hierarchy using the SHA256 versions of the
// provided PCRs.
// The Key k is used as the parent key.
func (k *Key) Unseal(in *proto.SealedBytes) ([]byte, error) {
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
		return nil, fmt.Errorf("failed to unseal: %v", err)
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

	return tpm2.UnsealWithSession(k.rw, session, sealed, "")
}

// Reseal unwraps a secret and rewraps it under the auth value that would be
// produced by the PCR state in pcrs. Similar to seal and unseal, this acts on
// the SHA256 PCRs and uses the owner hierarchy.
// The Key k is used as the parent key.
func (k *Key) Reseal(pcrs map[int][]byte, in *proto.SealedBytes) (*proto.SealedBytes, error) {
	sensitive, err := k.Unseal(in)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal: %v", err)
	}

	auth, err := computePCRSessionAuth(pcrs)
	if err != nil {
		return nil, fmt.Errorf("failed to compute pcr session auth: %v", err)
	}

	sb, err := sealHelper(k.rw, k.Handle(), auth, sensitive)
	if err != nil {
		return nil, err
	}
	for pcr := range pcrs {
		sb.Pcrs = append(sb.Pcrs, int32(pcr))
	}
	sb.Hash = in.Hash
	sb.Srk = in.Srk
	return sb, nil
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

	sel := tpm2.PCRSelection{
		Hash: tpm2.AlgSHA256,
		PCRs: pcrs,
	}
	if err = tpm2.PolicyPCR(rw, handle, nil, sel); err != nil {
		return tpm2.HandleNull, fmt.Errorf("auth step PolicyPCR failed: %v", err)
	}

	return handle, nil
}
