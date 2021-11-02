// Package cel contains some basic operations of Canonical Eventlog.
// Based on Canonical EventLog Spec (Draft) Version: TCG_IWG_CEL_v1_r0p37.
package cel

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"
	"io"

	"github.com/google/go-tpm/tpm2"
)

const (
	// CEL spec 5.1
	recnumTypeValue uint8 = 0
	pcrTypeValue    uint8 = 1
	// nvIndexTagValue uint8 = 2 // nvindex field is not supported yet
	digestsTypeValue uint8 = 3

	tlvTypeFieldLength   int = 1
	tlvLengthFieldLength int = 4

	recnumValueLength uint32 = 8 // support up to 2^64 records
	pcrValueLength    uint32 = 1 // support up to 256 PCRs
)

// TLV definition according to CEL spec TCG_IWG_CEL_v1_r0p37, page 16.
type TLV struct {
	Type   uint8
	Length uint32 // big-endian when encoding
	Value  []byte // with size of Length
}

// Marshal marhsals a TLV to a byte slice.
func (tlv *TLV) Marshal() ([]byte, error) {
	if tlv.Length != uint32(len(tlv.Value)) {
		return nil, fmt.Errorf("length of tlv.Value [%d] doesn't equal to tlv.Length [%d]",
			len(tlv.Value), tlv.Length)
	}

	buf := make([]byte, tlv.Length+uint32(tlvTypeFieldLength)+uint32(tlvLengthFieldLength))

	buf[0] = tlv.Type
	binary.BigEndian.PutUint32(buf[tlvTypeFieldLength:], tlv.Length)
	copy(buf[tlvTypeFieldLength+tlvLengthFieldLength:], tlv.Value)

	return buf, nil
}

// TLVUnmarshal reads and parse the first TLV from the bytes buffer. The function will
// return io.EOF if the buf ends unexpectedly or cannot filled the TLV.
func TLVUnmarshal(buf *bytes.Buffer) (TLV, error) {
	var tlv TLV
	var err error

	// read type
	tlv.Type, err = buf.ReadByte()
	if err != nil {
		return TLV{}, err
	}

	// read length
	b := make([]byte, tlvLengthFieldLength)
	l, err := buf.Read(b)
	if err != nil {
		return TLV{}, err
	}
	if l < tlvLengthFieldLength {
		return TLV{}, io.EOF
	}
	tlv.Length = binary.BigEndian.Uint32(b)

	// read value
	tlv.Value = make([]byte, tlv.Length)
	l, err = buf.Read(tlv.Value)
	if err != nil {
		return TLV{}, err
	}
	if l < int(tlv.Length) {
		return TLV{}, io.EOF
	}
	return tlv, nil
}

// Record represents a Canonical Eventlog Record.
type Record struct {
	RECNUM  TLV
	PCR     TLV
	Digests TLV
	Content TLV
}

// Content is a interface for the content in CELR.
type Content interface {
	GenerateDigest(crypto.Hash) ([]byte, error)
	GetTLV() TLV
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

		// TODO: extend the digest to TPM PCR
	}

	celr, err := createCELR(uint64(len(c.Records)), uint8(pcr), digestsMap, event)
	if err != nil {
		return err
	}

	c.Records = append(c.Records, celr)
	return nil
}

func createRecNumField(recNum uint64) TLV {
	value := make([]byte, recnumValueLength)
	binary.BigEndian.PutUint64(value, recNum)
	return TLV{recnumTypeValue, recnumValueLength, value}
}

// UnmarshalRecNum takes in a TLV with its tag equals to the recnum tag value (0), and
// return its record number.
func UnmarshalRecNum(tlv TLV) (uint64, error) {
	if tlv.Type != recnumTypeValue {
		return 0, fmt.Errorf("tag of the TLV [%d] indicates it is not a recnum field [%d]",
			tlv.Type, recnumTypeValue)
	}
	return binary.BigEndian.Uint64(tlv.Value), nil
}

func createPCRField(pcrNum uint8) TLV {
	return TLV{pcrTypeValue, pcrValueLength, []byte{pcrNum}}
}

// UnmarshalPCR takes in a TLV with its tag equals to the PCR tag value (1), and
// return its PCR number.
func UnmarshalPCR(tlv TLV) (pcrNum uint8, err error) {
	if tlv.Type != pcrTypeValue {
		return 0, fmt.Errorf("tag of the TLV [%d] indicates it is not a PCR field [%d]",
			tlv.Type, pcrTypeValue)
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
		singledigestTLV := TLV{uint8(tpmHashAlg), uint32(len(hash)), hash}
		d, err := singledigestTLV.Marshal()
		if err != nil {
			return TLV{}, err
		}
		_, err = buf.Write(d)
		if err != nil {
			return TLV{}, err
		}
	}
	return TLV{digestsTypeValue, uint32(buf.Len()), buf.Bytes()}, nil
}

// UnmarshalDigests takes in a TLV with its tag equals to the digests Tag value (3), and
// return its digests content in a map, the key is its TPM hash algorithm.
func UnmarshalDigests(tlv TLV) (digestsMap map[crypto.Hash][]byte, err error) {
	if tlv.Type != digestsTypeValue {
		return nil, fmt.Errorf("tag of the TLV indicates it doesn't contain digests")
	}

	buf := bytes.NewBuffer(tlv.Value)
	digestsMap = make(map[crypto.Hash][]byte)

	for buf.Len() > 0 {
		digestTLV, err := TLVUnmarshal(buf)
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

func createCELR(recNum uint64, pcr uint8, digestsmap map[crypto.Hash][]byte, event Content) (celr Record, err error) {
	recnumField := createRecNumField(recNum)
	pcrField := createPCRField(pcr)

	digestField, err := createDigestField(digestsmap)
	if err != nil {
		return Record{}, err
	}
	celr = Record{recnumField, pcrField, digestField, event.GetTLV()}

	return celr, nil
}

// EncodeCELR encodes the CELR to bytes according to the CEL spec and write them
// to the bytes byffer.
func (r *Record) EncodeCELR(buf *bytes.Buffer) error {
	recnumField, err := r.RECNUM.Marshal()
	if err != nil {
		return err
	}
	pcrField, err := r.PCR.Marshal()
	if err != nil {
		return err
	}
	digestsField, err := r.Digests.Marshal()
	if err != nil {
		return err
	}
	eventField, err := r.Content.Marshal()
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
func DecodeToCELR(buf *bytes.Buffer) (Record, error) {
	recnum, err := TLVUnmarshal(buf)
	if err != nil {
		return Record{}, err
	}
	if recnum.Type != recnumTypeValue {
		return Record{}, fmt.Errorf("recnum TLV doesn't have the correct type [%d], got [%d]",
			recnumTypeValue, recnum.Type)
	}

	pcr, err := TLVUnmarshal(buf)
	if err != nil {
		return Record{}, err
	}
	if pcr.Type != pcrTypeValue {
		return Record{}, fmt.Errorf("pcr TLV doesn't have the correct type [%d], got [%d]",
			pcrTypeValue, pcr.Type)
	}

	digests, err := TLVUnmarshal(buf)
	if err != nil {
		return Record{}, err
	}
	if digests.Type != digestsTypeValue {
		return Record{}, fmt.Errorf("digests TLV doesn't have the correct type [%d], got [%d]",
			digestsTypeValue, digests.Type)
	}

	content, err := TLVUnmarshal(buf)
	if err != nil {
		return Record{}, err
	}
	celr := Record{
		recnum,
		pcr,
		digests,
		content,
	}

	return celr, nil
}
