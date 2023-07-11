// Package utils contains crypto functionalities.
package utils

import (
	"crypto"
	"encoding/pem"
	"errors"
	"fmt"

	"github.com/google/certificate-transparency-go/x509"
)

const (
	// PKIXPublicKeyType is the PEM format separator used to parse PKIX-encoded public keys.
	PKIXPublicKeyType = "PUBLIC KEY"
	// PKCS1PublicKeyType is the PEM format separator used to parse PKCS1-encoded public keys.
	PKCS1PublicKeyType = "RSA PUBLIC KEY"
)

// UnmarshalPEMToPub converts a PEM-encoded byte slice into a crypto.PublicKey.
func UnmarshalPEMToPub(pemBytes []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM data found, failed to decode PEM-encoded byte slice")
	}
	switch block.Type {
	case PKIXPublicKeyType:
		return x509.ParsePKIXPublicKey(block.Bytes)
	case PKCS1PublicKeyType:
		return x509.ParsePKCS1PublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported public key type: %v", block.Type)
	}
}
