package cel

import (
	"crypto"
	"fmt"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	// CosEventType indicates the CELR event is a COS content
	// TODO: the value needs to be reserved in the CEL spec
	CosEventType uint8 = 80
	// CosEventPCR is the PCR which should be used for CosEventType events.
	CosEventPCR = 13
)

// CosType represent a COS content type in a CEL record content.
type CosType uint8

// Type for COS nested events
const (
	ImageRefType CosType = iota
	ImageDigestType
	RestartPolicyType
	ImageIDType
	ArgType
	EnvVarType
	OverrideArgType
	OverrideEnvType
	// EventContent is empty on success, or contains an error message on failure.
	LaunchSeparatorType
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

// FormatEnvVar takes in an environment variable name and its value, run some checks. Concats
// the name and value by '=' and returns it if valid; returns an error if the name or value
// is invalid.
func FormatEnvVar(name string, value string) (string, error) {
	if !utf8.ValidString(name) {
		return "", fmt.Errorf("malformed env name, contains non-utf8 character: [%s]", name)
	}
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("malformed env value, contains non-utf8 character: [%s]", value)
	}
	var envVarNameRegexp = regexp.MustCompile("^[a-zA-Z_][a-zA-Z0-9_]*$")
	if !envVarNameRegexp.MatchString(name) {
		return "", fmt.Errorf("malformed env name [%s], env name must start with an alpha character or '_', followed by a string of alphanumeric characters or '_' (%s)", name, envVarNameRegexp)
	}
	return name + "=" + value, nil
}

// ParseEnvVar takes in environment variable as a string (foo=bar), parses it and returns its name
// and value, or an error if it fails the validation check.
func ParseEnvVar(envvar string) (string, string, error) {
	// switch to strings.Cut when upgrading to go 1.18
	e := strings.SplitN(string(envvar), "=", 2)
	if len(e) < 2 {
		return "", "", fmt.Errorf("malformed env var, doesn't contain '=': [%s]", envvar)
	}

	if _, err := FormatEnvVar(e[0], e[1]); err != nil {
		return "", "", err
	}

	return e[0], e[1], nil
}
