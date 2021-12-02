package cel

import "crypto"

const (
	// CosTypeValue indicate the CELR event is a COS content
	// TODO: the value needs to be reserved in the CEL spec
	CosTypeValue uint8 = 80
)

// CosTlv is a specific event type created for the COS (Google Container-Optimized OS),
// used as a CEL content.
type CosTlv struct {
	data []byte // nested TLV
}

// GetTLV returns the TLV representation of the COS TLV.
func (c CosTlv) GetTLV() TLV {
	return TLV{
		Type:  CosTypeValue,
		Value: c.data,
	}
}

// GenerateDigest generates the digest for the given COS TLV. The whole TLV struct will
// be marshaled to bytes and feed into the hash algo.
func (c CosTlv) GenerateDigest(hashAlgo crypto.Hash) ([]byte, error) {
	contentTLV := c.GetTLV()
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
