package tpm2tools

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
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

	handle, pubArea, creationData, creationHash, ticket, name, err :=
		tpm2.CreatePrimaryEx(rw, parent, tpm2.PCRSelection{}, "", "", template)
	if err != nil {
		return
	}

	key = &Key{rw: rw, handle: handle, creationHash: creationHash, ticket: ticket}
	// Do not leak the key, only use bare returns in this function.
	defer func() {
		if err != nil {
			key.Close()
			key = nil
		}
	}()

	if key.pubArea, err = tpm2.DecodePublic(pubArea); err != nil {
		return
	}
	if key.pubArea.Type != tpm2.AlgRSA {
		err = fmt.Errorf("keys of type %v are not yet supported", key.pubArea.Type)
		return
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
	if lenDigest := len(key.name.Digest.Value); lenDigest != hashFn().Size() {
		err = fmt.Errorf("got len(digest) of %d, expected %d", lenDigest, hashFn().Size())
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

// SealedBytes stores the result of a TPM2_Seal. The private portion (priv) has
// already been encrypted and is no longer sensitive.
type SealedBytes struct {
	priv []byte
	pub  []byte
}

// Seal seals the sensitive byte buffer to the provided PCRs under the owner
// hierarchy using the SHA256 versions of the provided PCRs.
// The Key k is used as the parent key.
func (k *Key) Seal(pcrs []int, sensitive []byte) (SealedBytes, error) {
	auth, err := getPCRSessionAuth(k.rw, pcrs)
	if err != nil {
		return SealedBytes{}, fmt.Errorf("could not get pcr session auth: %v", err)
	}

	return sealHelper(k.rw, k.Handle(), auth, sensitive)
}

func sealHelper(rw io.ReadWriter, parentHandle tpmutil.Handle, auth []byte, sensitive []byte) (SealedBytes, error) {
	priv, pub, err := tpm2.Seal(rw, parentHandle, "", "", auth, sensitive)
	if err != nil {
		return SealedBytes{}, fmt.Errorf("failed to seal data: %v", err)
	}
	return SealedBytes{priv, pub}, nil
}

// Unseal takes a private/public pair of buffers and attempts to reverse the
// sealing process under the owner hierarchy using the SHA256 versions of the
// provided PCRs.
// The Key k is used as the parent key.
func (k *Key) Unseal(pcrs []int, in SealedBytes) ([]byte, error) {
	session, err := createPCRSession(k.rw, pcrs)
	if err != nil {
		return nil, fmt.Errorf("failed to unseal: %v", err)
	}
	defer tpm2.FlushContext(k.rw, session)

	sealed, _, err := tpm2.Load(
		k.rw,
		k.Handle(),
		/*parentPassword=*/ "",
		in.pub,
		in.priv)
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
func (k *Key) Reseal(pcrs map[int][]byte, in SealedBytes) (SealedBytes, error) {
	pcrNums := make([]int, 0, len(pcrs))
	for key := range pcrs {
		pcrNums = append(pcrNums, key)
	}

	sensitive, err := k.Unseal(pcrNums, in)
	if err != nil {
		return SealedBytes{}, fmt.Errorf("failed to unseal: %v", err)
	}

	auth, err := computePCRSessionAuth(pcrs)
	if err != nil {
		return SealedBytes{}, fmt.Errorf("failed to compute pcr session auth: %v", err)
	}

	return sealHelper(k.rw, k.Handle(), auth, sensitive)
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
