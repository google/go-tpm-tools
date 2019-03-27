package main

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
)

var (
	tpmPath   = flag.String("tpm-path", "/dev/tpm0", "Path to a TPM character device or socket.")
	hierarchy = flag.String("hierarchy", "endorsement", "Hierarchy to use for the key. Valid options are endorsement, platform, owner, and null.")
	index     = flag.Uint("template-index", 0, "NVRAM index of the key template; if zero, the default RSA EK/SRK template is used")
)

func main() {
	flag.Parse()

	rwc, err := tpm2.OpenTPM(*tpmPath)
	if err != nil {
		log.Fatalf("Failed to open TPM: %v", err)
	}
	defer rwc.Close()

	key, err := getKey(rwc, *hierarchy, uint32(*index))
	if err != nil {
		log.Fatalf("Failed to read public key: %v", err)
	}
	defer key.Close()

	if err := writeKey(key.PublicKey()); err != nil {
		log.Fatalf("Failed to write public key: %v", err)
	}
}

func getKey(rw io.ReadWriter, name string, idx uint32) (*tpm2tools.Key, error) {
	switch name {
	case "endorsement":
		if idx == 0 {
			return tpm2tools.EndorsementKeyRSA(rw)
		}
		return tpm2tools.EndorsementKeyFromNvIndex(rw, idx)
	case "owner":
		if idx == 0 {
			return tpm2tools.StorageRootKeyRSA(rw)
		}
		return tpm2tools.KeyFromNvIndex(rw, tpm2.HandleOwner, idx)
	case "platform":
		return tpm2tools.KeyFromNvIndex(rw, tpm2.HandlePlatform, idx)
	case "null":
		return tpm2tools.KeyFromNvIndex(rw, tpm2.HandleNull, idx)
	default:
		return nil, fmt.Errorf("invalid hierarchy %s", name)
	}
}

func writeKey(pubKey crypto.PublicKey) error {
	asn1Bytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return err
	}

	return pem.Encode(os.Stdout, &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: asn1Bytes,
	})
}
