package cel

import (
	"crypto"
	"fmt"
)

const (
	// CosEventType indicate the CELR event is a COS content
	// TODO: the value needs to be reserved in the CEL spec
	CosEventType uint8 = 80
)

// CosType represent a COS content type in a CEL record content.
type CosType uint8

// Type for COS nested events
const (
	ImageRefType CosType = iota
	ImageDigestType
	RestartPolicyType
)

// CosTlv is a specific event type created for the COS (Google Container-Optimized OS),
// used as a CEL content.
type CosTlv struct {
	EventType    CosType
	EventContent []byte
}

// GetTLV returns the TLV representation of the COS TLV.
func (c CosTlv) GetTLV() (TLV, error) {
	data, err := TLV{uint8(c.EventType), c.EventContent}.MarshalBinary()
	if err != nil {
		return TLV{}, err
	}

	return TLV{
		Type:  CosEventType,
		Value: data,
	}, nil
}

// GenerateDigest generates the digest for the given COS TLV. The whole TLV struct will
// be marshaled to bytes and feed into the hash algo.
func (c CosTlv) GenerateDigest(hashAlgo crypto.Hash) ([]byte, error) {
	contentTLV, err := c.GetTLV()
	if err != nil {
		return nil, err
	}

	b, err := contentTLV.MarshalBinary()
	if err != nil {
		return nil, err
	}

	hash := hashAlgo.New()
	if _, err = hash.Write(b); err != nil {
		return nil, err
	}
	return hash.Sum(nil), nil
}

// ParseToCosTlv constructs a CosTlv from a TLV. It will check for the correct COS event
// type, and unmarshal the nested event.
func (t TLV) ParseToCosTlv() (CosTlv, error) {
	if !t.IsCosTlv() {
		return CosTlv{}, fmt.Errorf("TLV type %v is not a COS event", t.Type)
	}
	nestedEvent := TLV{}
	err := nestedEvent.UnmarshalBinary(t.Value)
	if err != nil {
		return CosTlv{}, err
	}
	return CosTlv{CosType(nestedEvent.Type), nestedEvent.Value}, nil
}

// IsCosTlv check whether a TLV is a COS TLV by its Type value.
func (t TLV) IsCosTlv() bool {
	return t.Type == CosEventType
}
