package agent

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	"github.com/google/go-tpm-tools/launcher/internal/experiments"
	"github.com/google/go-tpm-tools/launcher/internal/signaturediscovery"
	"github.com/google/go-tpm-tools/launcher/spec"
	"github.com/google/go-tpm-tools/launcher/verifier"
	"github.com/google/go-tpm-tools/launcher/verifier/fake"
)

func TestAttest(t *testing.T) {
	testCases := []struct {
		name                       string
		launchSpec                 spec.LaunchSpec
		principalIDTokenFetcher    func(string) ([][]byte, error)
		containerSignaturesFetcher signaturediscovery.Fetcher
	}{
		{
			name:                       "all experiment flags disabled",
			launchSpec:                 spec.LaunchSpec{},
			principalIDTokenFetcher:    placeholderPrincipalFetcher,
			containerSignaturesFetcher: signaturediscovery.NewFakeClient(),
		},
		{
			name: "enable signed container",
			launchSpec: spec.LaunchSpec{
				SignedImageRepos: []string{signaturediscovery.FakeRepoWithSignatures},
				Experiments:      experiments.Experiments{EnableSignedContainerImage: true},
			},
			principalIDTokenFetcher:    placeholderPrincipalFetcher,
			containerSignaturesFetcher: signaturediscovery.NewFakeClient(),
		},
	}

	for _, tc := range testCases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			tpm := test.GetTPM(t)
			defer client.CheckedClose(t, tpm)

			fakeSigner, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Errorf("Failed to generate signing key %v", err)
			}

			verifierClient := fake.NewClient(fakeSigner)

			agent := CreateAttestationAgent(tpm, client.AttestationKeyECC, verifierClient, tc.principalIDTokenFetcher, tc.containerSignaturesFetcher, tc.launchSpec, log.Default())

			tokenBytes, err := agent.Attest(context.Background())
			if err != nil {
				t.Errorf("failed to attest to Attestation Service: %v", err)
			}

			claims := &fake.Claims{}
			keyFunc := func(token *jwt.Token) (interface{}, error) { return fakeSigner.Public(), nil }
			token, err := jwt.ParseWithClaims(string(tokenBytes), claims, keyFunc)
			if err != nil {
				t.Errorf("Failed to parse token %s", err)
			}

			if err = claims.Valid(); err != nil {
				t.Errorf("Invalid exp, iat, or nbf: %s", err)
			}

			if !claims.VerifyAudience("https://sts.googleapis.com/", true) {
				t.Errorf("Invalid aud")
			}

			if !claims.VerifyIssuer("https://confidentialcomputing.googleapis.com/", true) {
				t.Errorf("Invalid iss")
			}

			if claims.Subject != "https://www.googleapis.com/compute/v1/projects/fakeProject/zones/fakeZone/instances/fakeInstance" {
				t.Errorf("Invalid sub")
			}
			if tc.launchSpec.Experiments.EnableSignedContainerImage {
				got := claims.ContainerImageSignatures
				want := []fake.ContainerImageSignatureClaims{
					{
						Payload:   "test data",
						Signature: base64.StdEncoding.EncodeToString([]byte("test data")),
						PubKey:    "test data",
						SigAlg:    "ECDSA_P256_SHA256",
					},
					{
						Payload:   "hello world",
						Signature: base64.StdEncoding.EncodeToString([]byte("hello world")),
						PubKey:    "hello world",
						SigAlg:    "RSASSA_PKCS1V15_SHA256",
					},
				}
				if !cmp.Equal(got, want) {
					t.Errorf("ContainerImageSignatureClaims does not match expected value: got %v, want %v", got, want)
				}
			}
			fmt.Printf("token.Claims: %v\n", token.Claims)
		})
	}
}

func placeholderPrincipalFetcher(_ string) ([][]byte, error) {
	return [][]byte{}, nil
}

func TestFetchContainerImageSignatures(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name                string
		targetRepos         []string
		wantBase64Sigs      []string
		wantSignatureClaims []fake.ContainerImageSignatureClaims
		wantPartialErrLen   int
	}{
		{
			name:        "fetchContainerImageSignatures with repos that have signatures",
			targetRepos: []string{signaturediscovery.FakeRepoWithSignatures},
			wantBase64Sigs: []string{
				"dGVzdCBkYXRh",     // base64 encoded "test data".
				"aGVsbG8gd29ybGQ=", // base64 encoded "hello world".
			},
			wantSignatureClaims: []fake.ContainerImageSignatureClaims{
				{
					Payload:   "test data",
					Signature: base64.StdEncoding.EncodeToString([]byte("test data")),
					PubKey:    "test data",
					SigAlg:    "ECDSA_P256_SHA256",
				},
				{
					Payload:   "hello world",
					Signature: base64.StdEncoding.EncodeToString([]byte("hello world")),
					PubKey:    "hello world",
					SigAlg:    "RSASSA_PKCS1V15_SHA256",
				},
			},
			wantPartialErrLen: 0,
		},
		{
			name:                "fetchContainerImageSignatures with nil target repos",
			targetRepos:         nil,
			wantBase64Sigs:      nil,
			wantSignatureClaims: nil,
			wantPartialErrLen:   0,
		},
		{
			name:                "fetchContainerImageSignatures with empty target repos",
			targetRepos:         []string{},
			wantBase64Sigs:      nil,
			wantSignatureClaims: nil,
			wantPartialErrLen:   0,
		},
		{
			name:                "fetchContainerImageSignatures with non exist repos",
			targetRepos:         []string{signaturediscovery.FakeNonExistRepo},
			wantBase64Sigs:      nil,
			wantSignatureClaims: nil,
			wantPartialErrLen:   0,
		},
		{
			name:                "fetchContainerImageSignatures with repos that don't have signatures",
			targetRepos:         []string{signaturediscovery.FakeRepoWithNoSignatures},
			wantBase64Sigs:      nil,
			wantSignatureClaims: nil,
			wantPartialErrLen:   0,
		},
		{
			name:        "fetchContainerImageSignatures with repos that have all invalid signatures",
			targetRepos: []string{signaturediscovery.FakeRepoWithAllInvalidSignatures},
			wantBase64Sigs: []string{
				"aW52YWxpZCBzaWduYXR1cmU=", // base64 encoded "invalid signature".
				"aW52YWxpZCBzaWduYXR1cmU=", // base64 encoded "invalid signature".
			},
			wantSignatureClaims: nil,
			wantPartialErrLen:   2,
		},
		{
			name:        "fetchContainerImageSignatures with repos that have partial valid signatures",
			targetRepos: []string{signaturediscovery.FakeRepoWithPartialValidSignatures},
			wantBase64Sigs: []string{
				"dGVzdCBkYXRh",             // base64 encoded "test data".
				"aW52YWxpZCBzaWduYXR1cmU=", // base64 encoded "invalid signature".
			},
			wantSignatureClaims: []fake.ContainerImageSignatureClaims{
				{
					Payload:   "test data",
					Signature: base64.StdEncoding.EncodeToString([]byte("test data")),
					PubKey:    "test data",
					SigAlg:    "ECDSA_P256_SHA256",
				},
			},
			wantPartialErrLen: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sdClient := signaturediscovery.NewFakeClient()
			gotSigs := fetchContainerImageSignatures(ctx, sdClient, tc.targetRepos, log.Default())
			if len(gotSigs) != len(tc.wantBase64Sigs) {
				t.Errorf("fetchContainerImageSignatures did not return expected signatures for test case %s, got signatures length %d, but want %d", tc.name, len(gotSigs), len(tc.wantBase64Sigs))
			}
			var gotBase64Sigs []string
			for _, gotSig := range gotSigs {
				base64Sig, err := gotSig.Base64Encoded()
				if err != nil {
					t.Fatalf("fetchContainerImageSignatures did not return expected base64 signatures for test case %s: %v", tc.name, err)
				}
				gotBase64Sigs = append(gotBase64Sigs, base64Sig)
			}
			if !cmp.Equal(gotBase64Sigs, tc.wantBase64Sigs) {
				t.Errorf("fetchContainerImageSignatures did not return expected signatures for test case %s, got signatures %v, but want %v", tc.name, gotBase64Sigs, tc.wantBase64Sigs)
			}

			fakeSigner, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Errorf("Failed to generate signing key %v", err)
			}
			verifierClient := fake.NewClient(fakeSigner)
			req := verifier.VerifyAttestationRequest{
				ContainerImageSignatures: gotSigs,
			}
			got, err := verifierClient.VerifyAttestation(context.Background(), req)
			if err != nil {
				t.Fatalf("VerifyAttestation failed: %v", err)
			}
			claims := &fake.Claims{}
			keyFunc := func(token *jwt.Token) (interface{}, error) { return fakeSigner.Public(), nil }
			_, err = jwt.ParseWithClaims(string(got.ClaimsToken), claims, keyFunc)
			if err != nil {
				t.Errorf("Failed to parse token %s", err)
			}

			gotSignatureClaims := claims.ContainerImageSignatures
			if !cmp.Equal(gotSignatureClaims, tc.wantSignatureClaims) {
				t.Errorf("ContainerImageSignatureClaims does not match expected value: got %v, want %v", gotSignatureClaims, tc.wantSignatureClaims)
			}
			if len(got.PartialErrs) != tc.wantPartialErrLen {
				t.Errorf("VerifyAttestation did not return expected partial error length for test case %s, got partial errors length %d, but want %d", tc.name, len(got.ClaimsToken), tc.wantPartialErrLen)
			}
		})
	}
}
