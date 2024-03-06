package util

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/client"
	attestpb "github.com/google/go-tpm-tools/proto/attest"
)

// TpmKeyFetcher abstracts the fetching of various types of Attestation Key from TPM
type TpmKeyFetcher func(rw io.ReadWriter) (*client.Key, error)

// GetAttestation gathers the materials required for remote attestation from TPM
func GetAttestation(tpm io.ReadWriteCloser, akFetcher TpmKeyFetcher, nonce []byte) (*attestpb.Attestation, error) {
	ak, err := akFetcher(tpm)
	if err != nil {
		return nil, fmt.Errorf("failed to get AK: %v", err)
	}
	defer ak.Close()

	var buf bytes.Buffer
	coscel := &cel.CEL{}
	if err := coscel.EncodeCEL(&buf); err != nil {
		return nil, err
	}

	attestation, err := ak.Attest(client.AttestOpts{Nonce: nonce, CanonicalEventLog: buf.Bytes(), CertChainFetcher: http.DefaultClient})
	if err != nil {
		return nil, fmt.Errorf("failed to attest: %v", err)
	}
	return attestation, nil
}
