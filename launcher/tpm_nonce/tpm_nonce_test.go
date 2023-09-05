package tpmnonce

import (
	b64 "encoding/base64"
	"strings"
	"testing"
)

func TestGenerateTpmNonce(t *testing.T) {
	challenge := "GoogAttestV1lcdYd8KX3W3uESVrPbmTjA"
	nonces := [][]byte{
		[]byte("GoogAttestV1lddYd8KX3W3uESVrPbmTjA"),
		[]byte("ThisIsACustomNonce"),
	}

	tpmNonce, err := GenerateTpmNonce([]byte(challenge), nonces)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
		t.Fail()
	}
	if len(tpmNonce) != 44 {
		t.Errorf("expected a nonce 44 bytes long, got %d bytes", len(tpmNonce))
	}
	tpmNonceString := string(tpmNonce)
	if !strings.HasPrefix(tpmNonceString, "GoogAttestV2") {
		t.Errorf("expected a with prefix 'GoogAttestV2', actual nonce %v", tpmNonceString)
		t.Fail()
	}
}

func TestGenerateTpmNonceNilCustomNonces(t *testing.T) {
	challenge := "GoogAttestV1lcdYd8KX3W3uESVrPbmTjA"

	tpmNonce, err := GenerateTpmNonce([]byte(challenge), nil)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
		t.Fail()
	}
	if len(tpmNonce) != 44 {
		t.Errorf("expected a nonce 44 bytes long, got %d bytes", len(tpmNonce))
	}
	tpmNonceString := string(tpmNonce)
	if !strings.HasPrefix(tpmNonceString, "GoogAttestV2") {
		t.Errorf("expected a with prefix 'GoogAttestV2', actual nonce %v", tpmNonceString)
		t.Fail()
	}
}

func TestGenerateTpmNonceEmptyCustomNonces(t *testing.T) {
	challenge := "GoogAttestV1lcdYd8KX3W3uESVrPbmTjA"

	tpmNonce, err := GenerateTpmNonce([]byte(challenge), [][]byte{})

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if len(tpmNonce) != 44 {
		t.Errorf("expected a nonce 44 bytes long, got %d bytes", len(tpmNonce))
	}
	tpmNonceString := string(tpmNonce)
	if !strings.HasPrefix(tpmNonceString, "GoogAttestV2") {
		t.Errorf("expected a with prefix 'GoogAttestV2', actual nonce %v", tpmNonceString)
	}
}

func TestGenerateTpmNonceBase64ChallengeError(t *testing.T) {
	challenge := "GoogAttestV1lcdYd8KX3W3uESVrPbmTjA"
	base64Challenge := []byte(b64.StdEncoding.EncodeToString([]byte(challenge)))

	_, err := GenerateTpmNonce(base64Challenge, nil)

	if err == nil {
		t.Errorf("expected error")
	}
}

func TestGenerateTpmNonceNoChallengeError(t *testing.T) {
	challenge := ""

	_, err := GenerateTpmNonce([]byte(challenge), nil)

	if err == nil {
		t.Errorf("expected error")
	}
}
