package agent

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"math"
	"net/http"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal/test"
	"github.com/google/go-tpm-tools/launcher/internal/logging"
	"github.com/google/go-tpm-tools/launcher/internal/signaturediscovery"
	"github.com/google/go-tpm-tools/launcher/spec"
	attestpb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm-tools/verifier"
	"github.com/google/go-tpm-tools/verifier/fake"
	"github.com/google/go-tpm-tools/verifier/oci"
	"github.com/google/go-tpm-tools/verifier/oci/cosign"
	"github.com/google/go-tpm-tools/verifier/rest"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	imageRef      = "gcr.io/fakeRepo/fakeTestImage:latest"
	imageDigest   = "sha256:adb591795f9e9047f9117163b83c2ebcd5edc4503644d59a98cf911aef0367f8"
	restartPolicy = spec.Always
	imageID       = "sha256:d5496fd75dd8262f0495ab5706fc464659eb7f481e384700e6174b6c44144cae"
	arg           = "-h"
	envK          = "foo"
	envV          = "foo"
	env           = envK + "=" + envV
)

var (
	fakeProject = "confidentialcomputing-e2e"
	fakeRegion  = "us-central1"
)

func TestAttestRacing(t *testing.T) {
	ctx := context.Background()
	tpm := test.GetTPM(t)
	defer client.CheckedClose(t, tpm)

	fakeSigner, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate signing key %v", err)
	}

	verifierClient := fake.NewClient(fakeSigner)
	agent, err := CreateAttestationAgent(tpm, client.AttestationKeyECC, verifierClient, placeholderPrincipalFetcher, signaturediscovery.NewFakeClient(), spec.LaunchSpec{}, logging.SimpleLogger())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := agent.Attest(ctx, AttestAgentOpts{})
			if err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	agent.Close()
}

func TestAttestWithRetries(t *testing.T) {
	testCases := []struct {
		name         string
		fn           func(int) ([]byte, error)
		wantPass     bool
		wantAttempts int
	}{
		{
			name: "success",
			fn: func(int) ([]byte, error) {
				return []byte("test token"), nil
			},
			wantPass:     true,
			wantAttempts: 1,
		},
		{
			name: "failed with 500, then success",
			fn: func(attempts int) ([]byte, error) {
				if attempts == 1 {
					return nil, rest.NewVerifyAttestationError(nil, &googleapi.Error{Code: http.StatusInternalServerError})
				}
				return []byte("test token"), nil
			},
			wantPass:     true,
			wantAttempts: 2,
		},
		{
			name: "failed with 500 after attempts exceed",
			fn: func(int) ([]byte, error) {
				return nil, rest.NewVerifyAttestationError(nil, &googleapi.Error{Code: http.StatusInternalServerError})
			},
			wantPass:     false,
			wantAttempts: 4,
		},
		{
			name: "failed with non-500 error",
			fn: func(int) ([]byte, error) {
				return nil, fmt.Errorf("other error")
			},
			wantPass:     false,
			wantAttempts: 1,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Reset stub after test case is done.
			af := attestFunc
			t.Cleanup(func() { attestFunc = af })

			attempts := 0
			// Stub attestFunc.
			attestFunc = func(context.Context, *agent, AttestAgentOpts) ([]byte, error) {
				attempts++
				return tc.fn(attempts)
			}

			a := &agent{}
			testRetryPolicy := func() backoff.BackOff {
				return backoff.WithMaxRetries(backoff.NewConstantBackOff(time.Millisecond), 3)
			}
			_, err := a.AttestWithRetries(context.Background(), AttestAgentOpts{}, testRetryPolicy)
			if gotPass := (err == nil); gotPass != tc.wantPass {
				t.Errorf("AttestWithRetries failed, gotPass %v, but wantPass %v", gotPass, tc.wantPass)
			}

			if gotAttempts := attempts; gotAttempts != tc.wantAttempts {
				t.Errorf("AttestWithRetries failed, gotAttempts %v, but wantAttempts %v", gotAttempts, tc.wantAttempts)
			}
		})
	}
}

func TestAttest(t *testing.T) {
	ctx := context.Background()
	testCases := []struct {
		name                       string
		launchSpec                 spec.LaunchSpec
		principalIDTokenFetcher    func(string) ([][]byte, error)
		containerSignaturesFetcher signaturediscovery.Fetcher
	}{
		{
			name: "Happy path with container signatures",
			launchSpec: spec.LaunchSpec{
				SignedImageRepos: []string{signaturediscovery.FakeRepoWithSignatures},
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
				t.Fatalf("failed to generate signing key %v", err)
			}

			verifierClient := fake.NewClient(fakeSigner)

			agent, err := CreateAttestationAgent(tpm, client.AttestationKeyECC, verifierClient, tc.principalIDTokenFetcher, tc.containerSignaturesFetcher, tc.launchSpec, logging.SimpleLogger())
			if err != nil {
				t.Fatalf("failed to create an attestation agent %v", err)
			}
			err = measureFakeEvents(agent)
			if err != nil {
				t.Errorf("failed to measure events: %v", err)
			}
			if err := agent.Refresh(ctx); err != nil {
				t.Fatalf("failed to fresh attestation agent: %v", err)
			}
			tokenBytes, err := agent.Attest(ctx, AttestAgentOpts{})
			if err != nil {
				t.Fatalf("failed to attest to Attestation Service: %v", err)
			}
			agent.Close()

			claims := &fake.Claims{}
			keyFunc := func(_ *jwt.Token) (interface{}, error) { return fakeSigner.Public(), nil }
			token, err := jwt.ParseWithClaims(string(tokenBytes), claims, keyFunc)
			if err != nil {
				t.Errorf("failed to parse token %s", err)
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

			ms := &attestpb.MachineState{}
			err = protojson.Unmarshal([]byte(claims.MachineStateMarshaled), ms)
			if err != nil {
				t.Fatalf("failed to unmarshal claims as MachineState: %v", err)
			}
			validateContainerState(t, ms.GetCos())
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
			tpm := test.GetTPM(t)
			defer client.CheckedClose(t, tpm)
			ak, err := client.AttestationKeyECC(tpm)
			if err != nil {
				t.Fatalf("failed to create AK: %v", err)
			}

			testRetryPolicy := func() backoff.BackOff {
				b := backoff.NewExponentialBackOff()
				b.MaxElapsedTime = time.Millisecond
				return b
			}

			sdClient := signaturediscovery.NewFakeClient()
			gotSigs := fetchContainerImageSignatures(ctx, sdClient, tc.targetRepos, testRetryPolicy, logging.SimpleLogger())
			if len(gotSigs) != len(tc.wantBase64Sigs) {
				t.Errorf("fetchContainerImageSignatures did not return expected signatures for test case %s, got signatures length %d, but want %d", tc.name, len(gotSigs), len(tc.wantBase64Sigs))
			}
			gotBase64Sigs := convertOCISignatureToBase64(t, gotSigs)
			if !cmp.Equal(gotBase64Sigs, tc.wantBase64Sigs) {
				t.Errorf("fetchContainerImageSignatures did not return expected signatures for test case %s, got signatures %v, but want %v", tc.name, gotBase64Sigs, tc.wantBase64Sigs)
			}

			fakeSigner, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Errorf("failed to generate signing key %v", err)
			}
			verifierClient := fake.NewClient(fakeSigner)
			chal, err := verifierClient.CreateChallenge(ctx)
			if err != nil {
				t.Fatalf("failed to create challenge %v", err)
			}
			attestation, err := ak.Attest(client.AttestOpts{Nonce: chal.Nonce})
			if err != nil {
				t.Fatalf("failed to attest %v", err)
			}
			req := verifier.VerifyAttestationRequest{
				Attestation:              attestation,
				ContainerImageSignatures: gotSigs,
			}
			got, err := verifierClient.VerifyAttestation(context.Background(), req)
			if err != nil {
				t.Fatalf("VerifyAttestation failed: %v", err)
			}
			claims := &fake.Claims{}
			keyFunc := func(_ *jwt.Token) (interface{}, error) { return fakeSigner.Public(), nil }
			_, err = jwt.ParseWithClaims(string(got.ClaimsToken), claims, keyFunc)
			if err != nil {
				t.Errorf("failed to parse token %s", err)
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

// Represents the return value from FetchImageSignatures
type returnVal struct {
	result []oci.Signature
	err    error
}

// Implments signaturediscovery.Fetcher methods
type failingClient struct {
	mu       sync.Mutex
	results  map[string][]returnVal
	numTimes map[string]int
}

func NewFailingClient(mymap map[string][]returnVal) signaturediscovery.Fetcher {
	numTimes := map[string]int{}
	for k := range mymap {
		numTimes[k] = 0
	}
	return &failingClient{
		results:  mymap,
		numTimes: numTimes,
	}
}

// Return test data in a round robin fashion
func (f *failingClient) FetchImageSignatures(_ context.Context, targetRepository string) ([]oci.Signature, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	attempt := f.numTimes[targetRepository]
	r := f.results[targetRepository][attempt]
	f.numTimes[targetRepository] = intMin(attempt+1, len(f.results[targetRepository])-1)
	return r.result, r.err
}

func intMin(a, b int) int {
	return int(math.Min(float64(a), float64(b)))
}

func TestFetchContainerImageSignatures_RetriesOnFailure(t *testing.T) {
	ctx := context.Background()

	testCases := []struct {
		name      string
		resultmap map[string][]returnVal
	}{
		{
			name: "one repo, no failures",
			resultmap: map[string][]returnVal{
				"repo1": {
					returnVal{
						result: []oci.Signature{cosign.NewFakeSignature("test data", oci.ECDSAP256SHA256)},
						err:    nil,
					},
				},
			},
		},
		{
			name: "one repo fails",
			resultmap: map[string][]returnVal{
				"repo1": {
					returnVal{
						result: []oci.Signature{cosign.NewFakeSignature("test data", oci.ECDSAP256SHA256)},
						err:    fmt.Errorf("partial error"),
					},
				},
			},
		},
		{
			name: "one repo, failure then success",
			resultmap: map[string][]returnVal{
				"repo1": {
					returnVal{
						result: []oci.Signature{},
						err:    fmt.Errorf("failure 1"),
					},
					returnVal{
						result: []oci.Signature{cosign.NewFakeSignature("test data", oci.ECDSAP256SHA256)},
						err:    nil,
					},
				},
			},
		},
		{
			name: "two repos, no failures",
			resultmap: map[string][]returnVal{
				"repo1": {
					returnVal{
						result: []oci.Signature{cosign.NewFakeSignature("test data", oci.ECDSAP256SHA256)},
						err:    nil,
					},
				},
				"repo2": {
					returnVal{
						result: []oci.Signature{cosign.NewFakeSignature("test data again", oci.ECDSAP256SHA256)},
						err:    nil,
					},
				},
			},
		},
		{
			name: "two repos, failure then success",
			resultmap: map[string][]returnVal{
				"failrepo": {
					returnVal{
						result: []oci.Signature{},
						err:    fmt.Errorf("failure 1"),
					},
					returnVal{
						result: []oci.Signature{cosign.NewFakeSignature("test data", oci.ECDSAP256SHA256)},
						err:    nil,
					},
				},
				"successRepo": {
					returnVal{
						result: []oci.Signature{cosign.NewFakeSignature("test data again", oci.ECDSAP256SHA256)},
						err:    nil,
					},
				},
			},
		},
		{
			name: "two repos, failures",
			resultmap: map[string][]returnVal{
				"repo1": {
					returnVal{
						result: []oci.Signature{},
						err:    fmt.Errorf("failure 1"),
					},
				},
				"repo2": {
					returnVal{
						result: []oci.Signature{},
						err:    fmt.Errorf("failure 2"),
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sdClient := NewFailingClient(tc.resultmap)
			retryPolicy := func() backoff.BackOff {
				b := backoff.NewExponentialBackOff()
				return backoff.WithMaxRetries(b, 2)
			}

			repos := []string{}
			wantSigs := []oci.Signature{}
			for k, v := range tc.resultmap {
				repos = append(repos, k)
				for _, result := range v {
					if result.err == nil {
						wantSigs = append(wantSigs, result.result...)
					}
				}
			}

			gotSigs := fetchContainerImageSignatures(ctx, sdClient, repos, retryPolicy, logging.SimpleLogger())

			if len(gotSigs) != len(wantSigs) {
				t.Errorf("fetchContainerImageSignatures did not return expected signatures for test case %s, got signatures length %d, but want %d", tc.name, len(gotSigs), len(wantSigs))
			}
			if !cmp.Equal(convertOCISignatureToBase64(t, gotSigs), convertOCISignatureToBase64(t, wantSigs)) {
				t.Errorf("fetchContainerImageSignatures did not return expected signatures for test case %s, got signatures %v, but want %v", tc.name, gotSigs, wantSigs)
			}
		})
	}
}

func TestCacheConcurrentSetGet(t *testing.T) {
	cache := &sigsCache{}
	if sigs := cache.get(); len(sigs) != 0 {
		t.Errorf("signature cache should be empty, but got: %v", sigs)
	}

	var wg sync.WaitGroup
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			if idx%2 == 1 {
				sigs := generateRandSigs(t)
				cache.set(sigs)
			} else {
				cache.get()
			}
		}(i)
	}
	wg.Wait()
}

func generateRandSigs(t *testing.T) []oci.Signature {
	t.Helper()

	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		t.Fatalf("Unable to generate random bytes: %v", err)
	}

	randB64Str := base64.StdEncoding.EncodeToString(b)
	return []oci.Signature{
		cosign.NewFakeSignature(randB64Str, oci.ECDSAP256SHA256),
	}
}

func convertOCISignatureToBase64(t *testing.T, sigs []oci.Signature) []string {
	t.Helper()

	var base64Sigs []string
	for _, sig := range sigs {
		b64Sig, err := sig.Base64Encoded()
		if err != nil {
			t.Fatalf("oci.Signature did not return expected base64 signature: %v", err)
		}
		base64Sigs = append(base64Sigs, b64Sig)
	}

	return base64Sigs
}

// Skip the test if we are not running in an environment with Google API
func testClient(t *testing.T) verifier.Client {
	// TODO: Connect to the autopush endpoint by default.
	hClient, err := google.DefaultClient(context.Background())
	if err != nil {
		t.Skipf("Getting HTTP Client: %v", err)
	}

	vClient, err := rest.NewClient(context.Background(),
		fakeProject,
		fakeRegion,
		option.WithHTTPClient(hClient),
	)
	if err != nil {
		t.Fatalf("Creating Verifier Client: %v", err)
	}
	return vClient
}

func testPrincipalIDTokenFetcher(_ string) ([][]byte, error) {
	return [][]byte{}, nil
}

func TestWithAgent(t *testing.T) {
	vClient := testClient(t)

	tpm := test.GetTPM(t)
	defer client.CheckedClose(t, tpm)

	agent, err := CreateAttestationAgent(tpm, client.AttestationKeyECC, vClient, testPrincipalIDTokenFetcher, signaturediscovery.NewFakeClient(), spec.LaunchSpec{}, logging.SimpleLogger())
	if err != nil {
		t.Fatalf("failed to create an attestation agent %v", err)
	}
	defer agent.Close()

	token, err := agent.Attest(context.Background(), AttestAgentOpts{})
	if err != nil {
		t.Errorf("failed to attest to Attestation Service: %v", err)
	}
	t.Logf("Got Token: |%v|", string(token))
}

func validateContainerState(t *testing.T, cos *attestpb.AttestedCosState) {
	if cos == nil {
		t.Errorf("failed to find COS state in MachineState")
	}
	ctr := cos.GetContainer()
	if ctr == nil {
		t.Errorf("failed to find ContainerState in CosState")
		return
	}
	if ctr.ImageReference != imageRef {
		t.Errorf("got image ref %v, want image ref %v", ctr.ImageReference, imageRef)
	}
	if ctr.ImageDigest != imageDigest {
		t.Errorf("got image digest %v, want image digest %v", ctr.ImageDigest, imageDigest)
	}
	if ctr.RestartPolicy.String() != string(restartPolicy) {
		t.Errorf("got restart policy %v, want restart policy %v", ctr.RestartPolicy.String(), restartPolicy)
	}
	if len(ctr.Args) != 1 {
		t.Fatalf("got args %v, want length 1", ctr.Args)
	}
	if ctr.Args[0] != arg {
		t.Errorf("got args %v, want [%v]", ctr.Args, arg)
	}
	if len(ctr.OverriddenArgs) != 1 {
		t.Fatalf("got overridden args %v, want length 1", ctr.OverriddenArgs)
	}
	if ctr.OverriddenArgs[0] != arg {
		t.Errorf("got overridden args %v, want [%v]", ctr.OverriddenArgs, arg)
	}

	if len(ctr.EnvVars) != 1 {
		t.Fatalf("got envs %v, want length 1", ctr.EnvVars)
	}
	if val := ctr.EnvVars[envK]; val != envV {
		t.Errorf("got args %v, want map[%v]", ctr.EnvVars, env)
	}
	if len(ctr.OverriddenEnvVars) != 1 {
		t.Fatalf("got overridden envs %v, want length 1", ctr.OverriddenEnvVars)
	}
	if val := ctr.EnvVars[envK]; val != envV {
		t.Errorf("got overridden args %v, want map[%v]", ctr.OverriddenEnvVars, env)
	}
}

func measureFakeEvents(attestAgent AttestationAgent) error {
	if err := attestAgent.MeasureEvent(cel.CosTlv{EventType: cel.ImageRefType, EventContent: []byte(imageRef)}); err != nil {
		return err
	}
	if err := attestAgent.MeasureEvent(cel.CosTlv{EventType: cel.ImageDigestType, EventContent: []byte(imageDigest)}); err != nil {
		return err
	}
	if err := attestAgent.MeasureEvent(cel.CosTlv{EventType: cel.RestartPolicyType, EventContent: []byte(restartPolicy)}); err != nil {
		return err
	}
	if err := attestAgent.MeasureEvent(cel.CosTlv{EventType: cel.ImageIDType, EventContent: []byte(imageID)}); err != nil {
		return err
	}

	if err := attestAgent.MeasureEvent(cel.CosTlv{EventType: cel.ArgType, EventContent: []byte(arg)}); err != nil {
		return err
	}
	if err := attestAgent.MeasureEvent(cel.CosTlv{EventType: cel.EnvVarType, EventContent: []byte(env)}); err != nil {
		return err
	}

	if err := attestAgent.MeasureEvent(cel.CosTlv{EventType: cel.OverrideEnvType, EventContent: []byte(env)}); err != nil {
		return err
	}
	if err := attestAgent.MeasureEvent(cel.CosTlv{EventType: cel.OverrideArgType, EventContent: []byte(arg)}); err != nil {
		return err
	}
	return nil
}
