package fake

import (
	"crypto"
	_ "embed"
	"fmt"

	"github.com/golang-jwt/jwt/v4"
)

//go:embed signer_rsa
var testPrivateKeyBytes []byte

//go:embed signer_rsa.pub
var testPublicKeyBytes []byte

var testPrivateKey crypto.Signer
var testPublicKey crypto.PublicKey

func init() {
	var err error
	testPrivateKey, err = jwt.ParseRSAPrivateKeyFromPEM(testPrivateKeyBytes)
	if err != nil {
		panic(fmt.Sprintf("failed to parse embedded private key: %v", err))
	}
	testPublicKey, err = jwt.ParseRSAPublicKeyFromPEM(testPublicKeyBytes)
	if err != nil {
		panic(fmt.Sprintf("failed to parse embedded public key: %v", err))
	}
}

// TestPrivateKey returns the fake private key used for signing.
func TestPrivateKey() crypto.Signer {
	return testPrivateKey
}

// TestPublicKey returns the public key corresponding to the fake private key.
func TestPublicKey() any {
	return testPublicKey
}
