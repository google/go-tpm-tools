// Package util provides helper funtions to prepare materials for talking to attestation verifiers.
package util

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"cloud.google.com/go/compute/metadata"
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

// PrincipalFetcher fetch ID token with specific audience from Metadata server.
// See https://cloud.google.com/functions/docs/securing/authenticating#functions-bearer-token-example-go.
func PrincipalFetcher(audience string, mdsClient *metadata.Client) ([][]byte, error) {
	u := url.URL{
		Path: "instance/service-accounts/default/identity",
		RawQuery: url.Values{
			"audience": {audience},
			"format":   {"full"},
		}.Encode(),
	}
	idToken, err := mdsClient.Get(u.String())
	if err != nil {
		return nil, fmt.Errorf("failed to get principal tokens: %w", err)
	}

	tokens := [][]byte{[]byte(idToken)}
	return tokens, nil
}

// FetchAttestation gathers the materials required for remote attestation from TPM
func FetchAttestation(tpm io.ReadWriter, akFetcher TpmKeyFetcher, nonce []byte) (*attestpb.Attestation, error) {
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

// NewRESTClient returns a REST verifier.Client that points to the given address.
// It defaults to the Attestation Verifier instance at
// https://confidentialcomputing.googleapis.com.
func NewRESTClient(ctx context.Context, asAddr string, ProjectID string, Region string) (verifier.Client, error) {
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

// GetRegion retrieves region information from GCE metadata server
func GetRegion(client *metadata.Client) (string, error) {
	zone, err := client.Zone()
	if err != nil {
		return "", fmt.Errorf("failed to retrieve zone from MDS: %v", err)
	}
	lastDash := strings.LastIndex(zone, "-")
	if lastDash == -1 {
		return "", fmt.Errorf("got malformed zone from MDS: %v", zone)
	}
	return zone[:lastDash], nil
}
