// Package cel contains some basic operations of Canonical Eventlog.
// Based on Canonical EventLog Spec (Draft) Version: TCG_IWG_CEL_v1_r0p37.
package cel

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/google/go-configfs-tsm/configfs/configfsi"
	"github.com/google/go-eventlog/register"
	"github.com/google/go-tdx-guest/rtmr"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	// CEL spec 5.1
	recnumTypeValue uint8 = 0
	// PCRTypeValue indicates a PCR event index
	PCRTypeValue     uint8 = 1
	_                uint8 = 2 // nvindex field is not supported yet
	digestsTypeValue uint8 = 3
	// CCMRTypeValue indicates a RTMR event index
	CCMRTypeValue uint8 = 108 // not in the CEL spec

	tlvTypeFieldLength   int = 1
	tlvLengthFieldLength int = 4

	recnumValueLength   uint32 = 8 // support up to 2^64 records
	regIndexValueLength uint32 = 1 // support up to 256 registers
)

// TLV definition according to CEL spec TCG_IWG_CEL_v1_r0p37, page 16.
// Length is implicitly defined by len(Value), using uint32 big-endian
// when encoding.
type TLV struct {
	Type  uint8
	Value []byte
}

// MarshalBinary marshals a TLV to a byte slice.
func (t TLV) MarshalBinary() (data []byte, err error) {
	buf := make([]byte, len(t.Value)+tlvTypeFieldLength+tlvLengthFieldLength)

	buf[0] = t.Type
	binary.BigEndian.PutUint32(buf[tlvTypeFieldLength:], uint32(len(t.Value)))
	copy(buf[tlvTypeFieldLength+tlvLengthFieldLength:], t.Value)

	return buf, nil
}

// UnmarshalBinary unmarshal a byte slice to a TLV.
func (t *TLV) UnmarshalBinary(data []byte) error {
	valueLength := binary.BigEndian.Uint32(data[tlvTypeFieldLength : tlvTypeFieldLength+tlvLengthFieldLength])

	if valueLength != uint32(len(data[tlvTypeFieldLength+tlvLengthFieldLength:])) {
		return fmt.Errorf("TLV Length doesn't match the size of its Value")
	}
	t.Type = data[0]
	t.Value = data[tlvTypeFieldLength+tlvLengthFieldLength:]

	return nil
}

// UnmarshalFirstTLV reads and parse the first TLV from the bytes buffer. The function will
// return io.EOF if the buf ends unexpectedly or cannot fill the TLV.
func UnmarshalFirstTLV(buf *bytes.Buffer) (tlv TLV, err error) {
	typeByte, err := buf.ReadByte()
	if err != nil {
		return tlv, err
	}
	var data []byte
	data = append(data, typeByte)

	// get the length
	lengthBytes := make([]byte, tlvLengthFieldLength)
	bytesRead, err := buf.Read(lengthBytes)
	if err != nil {
		return TLV{}, err
	}
	if bytesRead != tlvLengthFieldLength {
		return TLV{}, io.EOF
	}
	valueLength := binary.BigEndian.Uint32(lengthBytes)
	data = append(data, lengthBytes...)

	valueBytes := make([]byte, valueLength)
	bytesRead, err = buf.Read(valueBytes)
	if err != nil {
		return TLV{}, err
	}
	if uint32(bytesRead) != valueLength {
		return TLV{}, io.EOF
	}
	data = append(data, valueBytes...)

	if err = (&tlv).UnmarshalBinary(data); err != nil {
		return TLV{}, err
	}
	return tlv, nil
}

// Record represents a Canonical Eventlog Record.
type Record struct {
	RecNum uint64
	// Generic Measurement Register index number, register type
	// is determined by IndexType
	Index     uint8
	IndexType uint8
	Digests   map[crypto.Hash][]byte
	Content   TLV
}

// Content is a interface for the content in CELR.
type Content interface {
	GenerateDigest(crypto.Hash) ([]byte, error)
	GetTLV() (TLV, error)
}

// CEL represents a Canonical Eventlog, which contains a list of Records.
type CEL struct {
	Records []Record
}

// generateDigestMap computes hashes with the given hash algos and the given event
func generateDigestMap(hashAlgos []crypto.Hash, event Content) (map[crypto.Hash][]byte, error) {
	digestsMap := make(map[crypto.Hash][]byte)
	for _, hashAlgo := range hashAlgos {
		digest, err := event.GenerateDigest(hashAlgo)
		if err != nil {
			return digestsMap, err
		}
		digestsMap[hashAlgo] = digest
	}
	return digestsMap, nil
}

// AppendEventRTMR appends a new RTMR record to the CEL. rtmrIndex indicates the RTMR to extend.
// The index showing up in the record will be rtmrIndex + 1.
func (c *CEL) AppendEventRTMR(client configfsi.Client, rtmrIndex int, event Content) error {
	digestsMap, err := generateDigestMap([]crypto.Hash{crypto.SHA384}, event)
	if err != nil {
		return err
	}

	eventTlv, err := event.GetTLV()
	if err != nil {
		return err
	}

	err = rtmr.ExtendDigestClient(client, rtmrIndex, digestsMap[crypto.SHA384])
	if err != nil {
		return err
	}

	celrRTMR := Record{
		RecNum:    uint64(len(c.Records)),
		Index:     uint8(rtmrIndex) + 1, // CCMR conversion from RTMR
		Digests:   digestsMap,
		Content:   eventTlv,
		IndexType: CCMRTypeValue,
	}

	c.Records = append(c.Records, celrRTMR)
	return nil
}

// AppendEvent appends a new PCR record to the CEL.
//
// Deprecated: Use AppendEventPCR or AppendEventRTMR directly.
func (c *CEL) AppendEvent(tpm io.ReadWriteCloser, pcr int, event Content) error {
	return c.AppendEventPCR(tpm, pcr, event)
}

// AppendEventPCR appends a new PCR record to the CEL and extend the digest of
// event to the given PCR in all available banks.
func (c *CEL) AppendEventPCR(tpm io.ReadWriteCloser, pcr int, event Content) error {
	pcrSels, err := client.AllocatedPCRs(tpm)
	if err != nil {
		return err
	}

	var hashAlgos []crypto.Hash
	for _, sel := range pcrSels {
		hashAlgo, err := sel.Hash.Hash()
		if err != nil {
			return err
		}
		hashAlgos = append(hashAlgos, hashAlgo)
	}

	digestsMap, err := generateDigestMap(hashAlgos, event)
	if err != nil {
		return err
	}

	for hs, dgst := range digestsMap {
		tpm2Alg, err := tpm2.HashToAlgorithm(hs)
		if err != nil {
			return err
		}
		if err := tpm2.PCRExtend(tpm, tpmutil.Handle(pcr), tpm2Alg, dgst, ""); err != nil {
			return fmt.Errorf("failed to extend event to PCR%d: %v", pcr, err)
		}
	}

	eventTlv, err := event.GetTLV()
	if err != nil {
		return err
	}

	celrPCR := Record{
		RecNum:    uint64(len(c.Records)),
		Index:     uint8(pcr),
		Digests:   digestsMap,
		Content:   eventTlv,
		IndexType: PCRTypeValue,
	}

	c.Records = append(c.Records, celrPCR)
	return nil
}

func createRecNumField(recNum uint64) TLV {
	value := make([]byte, recnumValueLength)
	binary.BigEndian.PutUint64(value, recNum)
	return TLV{recnumTypeValue, value}
}

// UnmarshalRecNum takes in a TLV with its type equals to the recnum type value (0), and
// return its record number.
func unmarshalRecNum(tlv TLV) (uint64, error) {
	if tlv.Type != recnumTypeValue {
		return 0, fmt.Errorf("type of the TLV [%d] indicates it is not a recnum field [%d]",
			tlv.Type, recnumTypeValue)
	}
	if uint32(len(tlv.Value)) != recnumValueLength {
		return 0, fmt.Errorf(
			"length of the value of the TLV [%d] doesn't match the defined length [%d] of value for recnum",
			len(tlv.Value), recnumValueLength)
	}
	return binary.BigEndian.Uint64(tlv.Value), nil
}

func createIndexField(indexType uint8, indexNum uint8) TLV {
	return TLV{indexType, []byte{indexNum}}
}

// unmarshalIndex takes in a TLV with its type equals to the PCR or CCMR type value, and
// return its index number.
func unmarshalIndex(tlv TLV) (indexType uint8, pcrNum uint8, err error) {
	if tlv.Type != PCRTypeValue && tlv.Type != CCMRTypeValue {
		return 0, 0, fmt.Errorf("type of the TLV [%d] indicates it is not a PCR [%d] or a CCMR [%d] field ",
			tlv.Type, PCRTypeValue, CCMRTypeValue)
	}
	if uint32(len(tlv.Value)) != regIndexValueLength {
		return 0, 0, fmt.Errorf(
			"length of the value of the TLV [%d] doesn't match the defined length [%d] of value for a register index field",
			len(tlv.Value), regIndexValueLength)
	}

	return tlv.Type, tlv.Value[0], nil
}

func createDigestField(digestMap map[crypto.Hash][]byte) (TLV, error) {
	var buf bytes.Buffer
	for hashAlgo, hash := range digestMap {
		if len(hash) != hashAlgo.Size() {
			return TLV{}, fmt.Errorf("digest length [%d] doesn't match the expected length [%d] for the hash algorithm",
				len(hash), hashAlgo.Size())
		}
		tpmHashAlg, err := tpm2.HashToAlgorithm(hashAlgo)
		if err != nil {
			return TLV{}, err
		}
		singleDigestTLV := TLV{uint8(tpmHashAlg), hash}
		d, err := singleDigestTLV.MarshalBinary()
		if err != nil {
			return TLV{}, err
		}
		_, err = buf.Write(d)
		if err != nil {
			return TLV{}, err
		}
	}
	return TLV{digestsTypeValue, buf.Bytes()}, nil
}

// UnmarshalDigests takes in a TLV with its type equals to the digests type value (3), and
// return its digests content in a map, the key is its TPM hash algorithm.
func unmarshalDigests(tlv TLV) (digestsMap map[crypto.Hash][]byte, err error) {
	if tlv.Type != digestsTypeValue {
		return nil, fmt.Errorf("type of the TLV indicates it doesn't contain digests")
	}

	buf := bytes.NewBuffer(tlv.Value)
	digestsMap = make(map[crypto.Hash][]byte)

	for buf.Len() > 0 {
		digestTLV, err := UnmarshalFirstTLV(buf)
		if err == io.EOF {
			return nil, fmt.Errorf("buffer ends unexpectedly")
		} else if err != nil {
			return nil, err
		}
		hashAlg, err := tpm2.Algorithm(digestTLV.Type).Hash()
		if err != nil {
			return nil, err
		}
		digestsMap[hashAlg] = digestTLV.Value
	}
	return digestsMap, nil
}

// EncodeCELR encodes the CELR to bytes according to the CEL spec and write them
// to the bytes byffer.
func (r *Record) EncodeCELR(buf *bytes.Buffer) error {
	recnumField, err := createRecNumField(r.RecNum).MarshalBinary()
	if err != nil {
		return err
	}

	indexField, err := createIndexField(r.IndexType, r.Index).MarshalBinary()
	if err != nil {
		return err
	}
	digests, err := createDigestField(r.Digests)
	if err != nil {
		return err
	}
	digestsField, err := digests.MarshalBinary()
	if err != nil {
		return err
	}
	eventField, err := r.Content.MarshalBinary()
	if err != nil {
		return err
	}
	_, err = buf.Write(recnumField)
	if err != nil {
		return err
	}
	_, err = buf.Write(indexField)
	if err != nil {
		return err
	}
	_, err = buf.Write(digestsField)
	if err != nil {
		return err
	}
	_, err = buf.Write(eventField)
	if err != nil {
		return err
	}
	return nil
}

// EncodeCEL encodes the CEL to bytes according to the CEL spec and write them
// to the bytes buffer.
func (c *CEL) EncodeCEL(buf *bytes.Buffer) error {
	for _, record := range c.Records {
		if err := record.EncodeCELR(buf); err != nil {
			return err
		}
	}
	return nil
}

// DecodeToCEL will read the buf for CEL, will return err if the buffer
// is not complete.
func DecodeToCEL(buf *bytes.Buffer) (CEL, error) {
	var cel CEL
	for buf.Len() > 0 {
		celr, err := DecodeToCELR(buf)
		if err == io.EOF {
			return CEL{}, fmt.Errorf("buffer ends unexpectedly")
		}
		if err != nil {
			return CEL{}, err
		}
		cel.Records = append(cel.Records, celr)
	}
	return cel, nil
}

// DecodeToCELR will read the buf for the next CELR, will return err if
// failed to unmarshal a correct CELR TLV from the buffer.
func DecodeToCELR(buf *bytes.Buffer) (r Record, err error) {
	recnum, err := UnmarshalFirstTLV(buf)
	if err != nil {
		return Record{}, err
	}
	r.RecNum, err = unmarshalRecNum(recnum)
	if err != nil {
		return Record{}, err
	}

	regIndex, err := UnmarshalFirstTLV(buf)
	if err != nil {
		return Record{}, err
	}
	r.IndexType, r.Index, err = unmarshalIndex(regIndex)
	if err != nil {
		return Record{}, err
	}

	digests, err := UnmarshalFirstTLV(buf)
	if err != nil {
		return Record{}, err
	}
	r.Digests, err = unmarshalDigests(digests)
	if err != nil {
		return Record{}, err
	}

	r.Content, err = UnmarshalFirstTLV(buf)
	if err != nil {
		return Record{}, err
	}
	return r, nil
}

// Replay takes the digests from a Canonical Event Log and carries out the
// extend sequence for each register (PCR, RTMR) in the log. It then compares
// the final digests against a bank of register values to see if they match.
// make sure CEL has only one indexType event
func (c *CEL) Replay(regs register.MRBank) error {
	cryptoHash, err := regs.CryptoHash()
	if err != nil {
		return err
	}
	replayed := make(map[uint8][]byte)
	for _, record := range c.Records {
		if _, ok := replayed[record.Index]; !ok {
			replayed[record.Index] = make([]byte, cryptoHash.Size())
		}
		hasher := cryptoHash.New()
		digestsMap := record.Digests
		digest, ok := digestsMap[cryptoHash]
		if !ok {
			return fmt.Errorf("the CEL record did not contain a %v digest", cryptoHash)
		}
		hasher.Write(replayed[record.Index])
		hasher.Write(digest)
		replayed[record.Index] = hasher.Sum(nil)
	}

	// to a map for easy matching
	registers := make(map[int][]byte)
	for _, r := range regs.MRs() {
		registers[r.Idx()] = r.Dgst()
	}

	var failedReplayRegs []uint8
	for replayReg, replayDigest := range replayed {
		bankDigest, ok := registers[int(replayReg)]
		if !ok {
			return fmt.Errorf("the CEL contains record(s) for register %d without a matching register in the given bank to verify", replayReg)
		}
		if !bytes.Equal(bankDigest, replayDigest) {
			failedReplayRegs = append(failedReplayRegs, replayReg)
		}
	}

	if len(failedReplayRegs) == 0 {
		return nil
	}

	return fmt.Errorf("CEL replay failed for these registers in bank %v: %v", cryptoHash, failedReplayRegs)
}

// VerifyDigests checks the digest generated by the given record's content to make sure they are equal to
// the digests in the digestMap.
func VerifyDigests(c Content, digestMap map[crypto.Hash][]byte) error {
	for hash, digest := range digestMap {
		generatedDigest, err := c.GenerateDigest(hash)
		if err != nil {
			return err
		}
		if !bytes.Equal(generatedDigest, digest) {
			return fmt.Errorf("CEL record content digest verification failed for %s", hash)
		}
	}
	return nil
}
