// scratch_test/test_ita_agent.go:go test -run TestITA ./launcher/scratch_test
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"unsafe"

	"github.com/google/go-tpm-tools/agent"
	gtcel "github.com/google/go-tpm-tools/cel"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/launcher/internal/gpu"
	"github.com/google/go-tpm-tools/verifier"
	"github.com/google/go-tpm-tools/verifier/ita"
	"github.com/google/go-tpm-tools/verifier/models"
	"github.com/google/go-tpm-tools/verifier/oci"
	tpm2 "github.com/google/go-tpm/legacy/tpm2"
)

const (
	apiURL = "https://api-dev02-user10.ita-dev.adsdcsp.com"
	apiKey = "djI6NzQ0MzUwZjQtZThmZS00YzU5LTkyNTItNDMyM2FhMzE0NDU1OkFsR0p0UEpPMjA5UWVMU0QxekowdTVBQ3pvODJ2ZHJnNzUwbUdBU2c="
)

type dummyLogger struct{}

func (d dummyLogger) Info(msg string, args ...any) {
	fmt.Printf("[INFO] "+msg+"\n", args...)
}
func (d dummyLogger) Error(msg string, args ...any) {
	fmt.Printf("[ERROR] "+msg+"\n", args...)
}

type dummySignatureFetcher struct{}

func (d dummySignatureFetcher) FetchImageSignatures(_ context.Context, _ string) ([]oci.Signature, error) {
	return nil, nil
}

func fetchGCPIdentityToken(audience string) (string, error) {
	client := &http.Client{}
	req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity?audience=%s&format=full", url.QueryEscape(audience)), nil)
	if err != nil {
		return "", err
	}
	req.Header.Add("Metadata-Flavor", "Google")
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("metadata server returned status %d: %s", resp.StatusCode, string(body))
	}
	return string(body), nil
}

func main() {
	ctx := context.Background()

	fmt.Println("1. Initializing production ITA Client...")
	itaClient, err := ita.NewClient(verifier.ITAConfig{
		ITARegion: "US",
		ITAKey:    apiKey,
	})
	if err != nil {
		panic(err)
	}
	overrideClientURL(itaClient, apiURL)

	fmt.Println("2. Opening TPM...")
	tpm, err := tpm2.OpenTPM("/dev/tpmrm0")
	if err != nil {
		panic(err)
	}
	defer tpm.Close()

	fmt.Println("3. Creating Nvidia Attester...")
	nvidiaAttester := gpu.NewNvidiaAttester(true)
	if err := nvidiaAttester.EnableReadyState(); err != nil {
		fmt.Printf("Warning: failed to set GPU state to ready: %v\n", err)
	}

	principalFetcher := func(audience string) ([][]byte, error) {
		fmt.Printf("PrincipalFetcher called for audience: %s\n", audience)
		tok, err := fetchGCPIdentityToken(audience)
		if err != nil {
			return nil, err
		}
		return [][]byte{[]byte(tok)}, nil
	}

	exps := agent.Experiments{
		EnableGpuGcaSupport:       true,
		EnableGpuItaSupport:       true,
		EnableAttestationEvidence: true,
	}

	fmt.Println("4. Creating Attestation Agent...")
	attestAgent, err := agent.CreateAttestationAgent(
		tpm,
		client.GceAttestationKeyECC,
		itaClient,
		principalFetcher,
		dummySignatureFetcher{},
		exps,
		dummyLogger{},
		[]agent.DeviceROT{nvidiaAttester},
		nil, // signedImageRepos
	)
	if err != nil {
		panic(err)
	}

	fmt.Println("4.5. Measuring dummy event...")
	err = attestAgent.MeasureEvent(gtcel.CosTlv{
		EventType:    gtcel.ArgType,
		EventContent: []byte("dummy-arg"),
	})
	if err != nil {
		panic(fmt.Sprintf("MeasureEvent failed: %v", err))
	}

	fmt.Println("5. Invoking AttestWithClient...")
	opts := agent.AttestAgentOpts{
		TokenOptions: &models.TokenOptions{
			Audience:  "https://sts.googleapis.com",
			TokenType: "OIDC",
		},
		DeviceReportOpts: &agent.DeviceReportOpts{
			EnableRuntimeGPUAttestation: true,
		},
	}

	token, err := attestAgent.AttestWithClient(ctx, opts, itaClient)
	if err != nil {
		panic(fmt.Sprintf("AttestWithClient failed: %v", err))
	}

	fmt.Println("\n--- ATTESTATION TOKEN RECEIVED FROM AGENT.ATTESTWITHCLIENT ---")
	fmt.Println(string(token))
	fmt.Println("-------------------------------------------------------------")
}

func overrideClientURL(c verifier.Client, newURL string) {
	val := reflect.ValueOf(c).Elem()
	field := val.FieldByName("apiURL")
	if field.IsValid() {
		ptr := reflect.NewAt(field.Type(), unsafe.Pointer(field.UnsafeAddr())).Elem()
		ptr.SetString(newURL)
	}
}
