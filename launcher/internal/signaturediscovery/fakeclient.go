package signaturediscovery

import (
	"context"
	"fmt"

	"github.com/google/go-tpm-tools/launcher/internal/oci"
	"github.com/google/go-tpm-tools/launcher/internal/oci/cosign"
)

const (
	// FakeRepoWithSignatures represents an OCI registry with container image signatures for testing.
	FakeRepoWithSignatures = "repo with signatures"
	// FakeRepoWithNoSignatures represents an OCI registry with no container image signatures for testing.
	FakeRepoWithNoSignatures = "repo with no signatures"
	// FakeNonExistRepo represents a non-exist OCI registry for testing.
	FakeNonExistRepo = "nonexist repo"
	// FakeRepoWithAllInvalidSignatures represents an OCI registry with all invalid container image signatures for testing.
	FakeRepoWithAllInvalidSignatures = "repo with all invalid signatures"
	// FakeRepoWithPartialValidSignatures represents an OCI registry with parital valid container image signatures for testing.
	FakeRepoWithPartialValidSignatures = "repo with parital valid signatures"
)

type fakeClient struct{}

// NewFakeClient constructs a new fake signature discovery client.
func NewFakeClient() Fetcher {
	return &fakeClient{}
}

// FetchImageSignatures returns hardcoded signatures based on the given target repository.
func (f *fakeClient) FetchImageSignatures(_ context.Context, targetRepository string) ([]oci.Signature, error) {
	switch targetRepository {
	case FakeRepoWithSignatures:
		return []oci.Signature{
			cosign.NewFakeSignature("test data", oci.ECDSAP256SHA256),
			cosign.NewFakeSignature("hello world", oci.RSASSAPKCS1V152048SHA256),
		}, nil
	case FakeRepoWithNoSignatures, FakeNonExistRepo:
		return nil, fmt.Errorf("cannot fetch the signature object from target repository [%s]", targetRepository)
	case FakeRepoWithAllInvalidSignatures:
		return []oci.Signature{
			cosign.NewFakeSignature("invalid signature", "unsupported"),
			cosign.NewFakeSignature("invalid signature", "unsupported"),
		}, nil
	case FakeRepoWithPartialValidSignatures:
		return []oci.Signature{
			cosign.NewFakeSignature("test data", oci.ECDSAP256SHA256),
			cosign.NewFakeSignature("invalid signature", "unsupported"),
		}, nil
	default:
		return []oci.Signature{}, nil
	}
}
