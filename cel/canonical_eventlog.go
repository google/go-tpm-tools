// Package cel contains some basic operations of Canonical Eventlog.
// Based on Canonical EventLog Spec (Draft) Version: TCG_IWG_CEL_v1_r0p37.
package cel

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"
	"io"

	pb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
)

const (
	// CEL spec 5.1
	recnumTypeValue  uint8 = 0
	pcrTypeValue     uint8 = 1
	_                uint8 = 2 // nvindex field is not supported yet
	digestsTypeValue uint8 = 3

	tlvTypeFieldLength   int = 1
	tlvLengthFieldLength int = 4

	recnumValueLength uint32 = 8 // support up to 2^64 records
	pcrValueLength    uint32 = 1 // support up to 256 PCRs
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
	RecNum  uint64
	PCR     uint8
	Digests map[crypto.Hash][]byte
	Content TLV
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

// AppendEvent appends a new record to the CEL.
func (c *CEL) AppendEvent(tpm io.ReadWriteCloser, pcr int, hashAlgos []crypto.Hash, event Content) error {
	if len(hashAlgos) == 0 {
		return fmt.Errorf("need to specify at least one hash algorithm")
	}
	digestsMap := make(map[crypto.Hash][]byte)

	for _, hashAlgo := range hashAlgos {
		digest, err := event.GenerateDigest(hashAlgo)
		if err != nil {
			return err
		}
		digestsMap[hashAlgo] = digest

		tpm2Alg, err := tpm2.HashToAlgorithm(hashAlgo)
		if err != nil {
			return err
		}
		if err := tpm2.PCRExtend(tpm, tpmutil.Handle(pcr), tpm2Alg, digest, ""); err != nil {
			return fmt.Errorf("failed to extend event to PCR%d: %v", pcr, err)
		}
	}

	eventTlv, err := event.GetTLV()
	if err != nil {
		return err
	}

	celr := Record{
		RecNum:  uint64(len(c.Records)),
		PCR:     uint8(pcr),
		Digests: digestsMap,
		Content: eventTlv,
	}

	c.Records = append(c.Records, celr)
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

func createPCRField(pcrNum uint8) TLV {
	return TLV{pcrTypeValue, []byte{pcrNum}}
}

// UnmarshalPCR takes in a TLV with its type equals to the PCR type value (1), and
// return its PCR number.
func unmarshalPCR(tlv TLV) (pcrNum uint8, err error) {
	if tlv.Type != pcrTypeValue {
		return 0, fmt.Errorf("type of the TLV [%d] indicates it is not a PCR field [%d]",
			tlv.Type, pcrTypeValue)
	}
	if uint32(len(tlv.Value)) != pcrValueLength {
		return 0, fmt.Errorf(
			"length of the value of the TLV [%d] doesn't match the defined length [%d] of value for a PCR field",
			len(tlv.Value), pcrValueLength)
	}

	return tlv.Value[0], nil
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
	pcrField, err := createPCRField(r.PCR).MarshalBinary()
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
	_, err = buf.Write(pcrField)
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

	pcr, err := UnmarshalFirstTLV(buf)
	if err != nil {
		return Record{}, err
	}
	r.PCR, err = unmarshalPCR(pcr)
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
// extend sequence for each PCR in the log. It then compares the final digests
// against a bank of PCR values to see if they match.
func (c *CEL) Replay(bank *pb.PCRs) error {
	tpm2Alg := tpm2.Algorithm(bank.GetHash())
	cryptoHash, err := tpm2Alg.Hash()
	if err != nil {
		return err
	}
	replayed := make(map[uint8][]byte)
	for _, record := range c.Records {
		if _, ok := replayed[record.PCR]; !ok {
			replayed[record.PCR] = make([]byte, cryptoHash.Size())
		}
		hasher := cryptoHash.New()
		digestsMap := record.Digests
		digest, ok := digestsMap[cryptoHash]
		if !ok {
			return fmt.Errorf("the CEL record did not contain a %v digest", cryptoHash)
		}
		hasher.Write(replayed[record.PCR])
		hasher.Write(digest)
		replayed[record.PCR] = hasher.Sum(nil)
	}

	var failedReplayPcrs []uint8
	for replayPcr, replayDigest := range replayed {
		bankDigest, ok := bank.Pcrs[uint32(replayPcr)]
		if !ok {
			return fmt.Errorf("the CEL contained record(s) for PCR%d without a matching PCR in the bank to verify", replayPcr)
		}
		if !bytes.Equal(bankDigest, replayDigest) {
			failedReplayPcrs = append(failedReplayPcrs, replayPcr)
		}
	}

	if len(failedReplayPcrs) == 0 {
		return nil
	}

	return fmt.Errorf("CEL replay failed for these PCRs in bank %v: %v", cryptoHash, failedReplayPcrs)
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
