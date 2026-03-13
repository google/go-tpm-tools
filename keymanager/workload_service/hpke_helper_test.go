//go:build integration

package workloadservice

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"testing"

	"golang.org/x/crypto/hkdf"
)

const hpkeVersion = "HPKE-v1"

// hpkeLabeledExtract implements the HPKE LabeledExtract function.
// It derives a pseudorandom key (PRK) from the input keying material (IKM).
func hpkeLabeledExtract(suiteID []byte, label string, ikm []byte) []byte {
	labeledIKM := append([]byte(hpkeVersion), suiteID...)
	labeledIKM = append(labeledIKM, []byte(label)...)
	labeledIKM = append(labeledIKM, ikm...)
	return hkdf.Extract(sha256.New, labeledIKM, nil)
}

// hpkeLabeledExpand implements the HPKE LabeledExpand function.
// It expands a pseudorandom key (PRK) into a string of length `length`.
func hpkeLabeledExpand(prk []byte, suiteID []byte, label string, info []byte, length int) ([]byte, error) {
	var labeledInfo []byte
	labeledInfo = append(labeledInfo, byte(length>>8), byte(length))
	labeledInfo = append(labeledInfo, []byte(hpkeVersion)...)
	labeledInfo = append(labeledInfo, suiteID...)
	labeledInfo = append(labeledInfo, []byte(label)...)
	labeledInfo = append(labeledInfo, info...)
	r := hkdf.Expand(sha256.New, prk, labeledInfo)
	k := make([]byte, length)
	if _, err := io.ReadFull(r, k); err != nil {
		return nil, err
	}
	return k, nil
}

// encapsulateDHKEMX25519HKDFSHA256 performs DHKEM encapsulation for X25519-HKDF-SHA256.
// It generates an ephemeral keypair, computes the DH shared secret with the recipient's
// public key, and derives the HPKE shared secret using labeled extract and expand.
// Returns the derived shared secret and its corresponding ephemeral public key (enc).
func encapsulateDHKEMX25519HKDFSHA256(pkR []byte) (sharedSecret []byte, enc []byte, err error) {
	// Generate ephemeral keypair
	skE, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ephemeral key: %v", err)
	}
	pkE := skE.PublicKey().Bytes()

	// Compute DH shared secret
	dhPeer, err := ecdh.X25519().NewPublicKey(pkR)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse recipient public key: %v", err)
	}
	dh, err := skE.ECDH(dhPeer)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to compute DH: %v", err)
	}

	// Compute kem_context = pkE || pkR
	kemContext := append(pkE, pkR...)

	// Compute suite_id = "KEM" || I2OSP(32, 2)
	suiteID := []byte("KEM\x00\x20")

	// Extract and Expand
	prk := hpkeLabeledExtract(suiteID, "eae_prk", dh)
	sharedSecret, err = hpkeLabeledExpand(prk, suiteID, "shared_secret", kemContext, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to expand shared secret: %v", err)
	}

	return sharedSecret, pkE, nil
}

// TestValidateDHKEMHelpers validates the HPKE helper functions using test vectors
// from RFC 9180 Appendix A.1.
func TestValidateDHKEMHelpers(t *testing.T) {
	// Values from RFC 9180 Appendix A.1 https://www.rfc-editor.org/rfc/rfc9180.html#appendix-A.1
	pkRmHex := "3948cfe0ad1ddb695d780e59077195da6c56506b027329794ab02bca80815c4d"
	// skRmHex := "4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8"
	pkEmHex := "37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"
	skEmHex := "52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"
	sharedSecretHex := "fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc"

	pkRm, _ := hex.DecodeString(pkRmHex)
	// skRm, _ := hex.DecodeString(skRmHex)
	pkEm, _ := hex.DecodeString(pkEmHex)
	skEm, _ := hex.DecodeString(skEmHex)
	expectedSharedSecret, _ := hex.DecodeString(sharedSecretHex)

	// Compute DH shared secret manually using test vector keys
	dhPeer, err := ecdh.X25519().NewPublicKey(pkRm)
	if err != nil {
		t.Fatalf("failed to parse pkRm: %v", err)
	}
	skE, err := ecdh.X25519().NewPrivateKey(skEm)
	if err != nil {
		t.Fatalf("failed to create skE: %v", err)
	}
	dh, err := skE.ECDH(dhPeer)
	if err != nil {
		t.Fatalf("failed to compute DH: %v", err)
	}

	// Compute kem_context = pkE || pkR
	kemContext := append(pkEm, pkRm...)

	// Compute suite_id = "KEM" || I2OSP(32, 2)
	suiteID := []byte("KEM\x00\x20")

	// Extract and Expand
	prk := hpkeLabeledExtract(suiteID, "eae_prk", dh)
	calculatedSharedSecret, err := hpkeLabeledExpand(prk, suiteID, "shared_secret", kemContext, 32)
	if err != nil {
		t.Fatalf("failed to expand shared secret: %v", err)
	}

	if !bytes.Equal(calculatedSharedSecret, expectedSharedSecret) {
		t.Errorf("shared secret mismatch.\nExpected: %s\nGot:      %x", sharedSecretHex, calculatedSharedSecret)
	}
}
