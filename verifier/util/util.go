// Package util provides helper funtions to prepare materials for talking to attestation verifiers.
package util

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"

	"github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/client"
	attestpb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/verifier"
	"github.com/google/go-tpm-tools/verifier/rest"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
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

// GetRESTClient returns a REST verifier.Client that points to the given address.
// It defaults to the Attestation Verifier instance at
// https://confidentialcomputing.googleapis.com.
func GetRESTClient(ctx context.Context, asAddr string, ProjectID string, Region string) (verifier.Client, error) {
	httpClient, err := google.DefaultClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %v", err)
	}

	opts := []option.ClientOption{option.WithHTTPClient(httpClient)}
	if asAddr != "" {
		opts = append(opts, option.WithEndpoint(asAddr))
	}

	restClient, err := rest.NewClient(ctx, ProjectID, Region, opts...)
	if err != nil {
		return nil, err
	}
	return restClient, nil
}
