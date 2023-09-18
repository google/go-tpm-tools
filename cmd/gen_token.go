package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"os"
	"strings"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/containerd/containerd/namespaces"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/launcher/agent"
	"github.com/google/go-tpm-tools/launcher/verifier"
	"github.com/google/go-tpm-tools/launcher/verifier/rest"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

const (
	successRC = 0 // workload successful (no reboot)
	failRC    = 1 // workload or launcher internal failed (no reboot)
	// panic() returns 2
	rebootRC = 3 // reboot
	holdRC   = 4 // hold
)

var rcMessage = map[int]string{
	successRC: "workload finished successfully, shutting down the VM",
	failRC:    "workload or launcher error, shutting down the VM",
	rebootRC:  "rebooting VM",
	holdRC:    "VM remains running",
}

var logger *log.Logger
var mdsClient *metadata.Client

// If hardware technology needs a variable length teenonce then please modify the flags description
var gentokenCmd = &cobra.Command{
	Use:   "gentoken",
	Short: "Attest and fetch an OIDC token from Google Attestation Verification Service. Note that this command will only work on a GCE VM. Confidential computing API needs to be enabled to access Google Attestation Verification Service https://pantheon.corp.google.com/apis/api/confidentialcomputing.googleapis.com.",
	Long: `Gather attestation report and send it to Google Attestation Verification Service for an OIDC token.
The Attestation report contains a quote on all available PCR banks, a way to validate the quote, and a TCG Event Log (Linux only). The OIDC token includes claims regarding the authentication of the user by the authorization server (Google IAM server) with the use of an OAuth client application(Google Cloud apps).
Use --key to specify the type of attestation key. It can be gceAK for GCE attestation
key or AK for a custom attestation key. By default it uses AK.
--algo flag overrides the public key algorithm for attestation key. If not provided then
by default rsa is used.
--tee-nonce attaches a 64 bytes extra data to the attestation report of TDX and SEV-SNP 
hardware and guarantees a fresh quote.
`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		// Generate attestation report
		rwc, err := openTpm()
		if err != nil {
			return err
		}
		defer rwc.Close()

		var attestationKey *client.Key
		algoToCreateAK, ok := attestationKeys[key]
		if !ok {
			return fmt.Errorf("key should be either AK or gceAK")
		}
		createFunc := algoToCreateAK[keyAlgo]
		attestationKey, err = createFunc(rwc)
		if err != nil {
			return fmt.Errorf("failed to create attestation key: %v", err)
		}
		defer attestationKey.Close()

		attestOpts := client.AttestOpts{}
		attestOpts.Nonce = nonce

		// Add logic to open other hardware devices when required.
		switch teeTechnology {
		case SevSnp:
			attestOpts.TEEDevice, err = client.CreateSevSnpDevice()
			if err != nil {
				return fmt.Errorf("failed to open %s device: %v", SevSnp, err)
			}
			attestOpts.TEENonce = teeNonce
		case Tdx:
			attestOpts.TEEDevice, err = client.CreateTdxDevice()
			if err != nil {
				return fmt.Errorf("failed to open %s device: %v", Tdx, err)
			}
			attestOpts.TEENonce = teeNonce
		case "":
			if len(teeNonce) != 0 {
				return fmt.Errorf("use of --tee-nonce requires specifying TEE hardware type with --tee-technology")
			}
		default:
			// Change the return statement when more devices are added
			return fmt.Errorf("tee-technology should be either empty or should have values %s or %s", SevSnp, Tdx)
		}

		attestOpts.TCGEventLog, err = client.GetEventLog(rwc)
		if err != nil {
			return fmt.Errorf("failed to retrieve TCG Event Log: %w", err)
		}

		attestation, err := attestationKey.Attest(attestOpts)
		if err != nil {
			return fmt.Errorf("failed to collect attestation report : %v", err)
		}

		if key == "gceAK" {
			instanceInfo, err := getInstanceInfoFromMetadata()
			if err != nil {
				return err
			}
			attestation.InstanceInfo = instanceInfo
		}

		// Send attestation report to Attestation Verification Server

		logger = log.Default()
		// log.Default() outputs to stderr; change to stdout.
		log.SetOutput(os.Stdout)
		logger.Println("TEE container launcher initiating")

		var exitCode int
		// Get RestartPolicy and IsHardened from spec
		mdsClient = metadata.NewClient(nil)

		defer func() {
			// Catch panic to attempt to output to Cloud Logging.
			if r := recover(); r != nil {
				logger.Println("Panic:", r)
				exitCode = 2
			}
			msg, ok := rcMessage[exitCode]
			if ok {
				logger.Printf("TEE container launcher exiting with exit code: %d (%s)\n", exitCode, msg)
			} else {
				logger.Printf("TEE container launcher exiting with exit code: %d\n", exitCode)
			}
		}()

		ctx := namespaces.WithNamespace(context.Background(), namespaces.Default)
		// Fetch ID token with specific audience.
		// See https://cloud.google.com/functions/docs/securing/authenticating#functions-bearer-token-example-go.
		principalFetcher := func(audience string) ([][]byte, error) {
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

		// TODO: make this an optional flag
		asAddr := "https://confidentialcomputing.googleapis.com"

		Region, err := getRegion(mdsClient)
		if err != nil {
			return fmt.Errorf("failed to fetch Region from MDS: %v", err)
		}

		ProjectID, err := mdsClient.ProjectID()
		if err != nil {
			return fmt.Errorf("failed to retrieve ProjectID from MDS: %v", err)
		}

		verifierClient, err := getRESTClient(ctx, asAddr, ProjectID, Region)
		if err != nil {
			return fmt.Errorf("failed to create REST verifier client: %v", err)
		}

		// check AK (EK signing) cert
		gceAk, err := client.GceAttestationKeyECC(rwc)
		if err != nil {
			return err
		}
		if gceAk.Cert() == nil {
			return errors.New("failed to find AKCert on this VM: try creating a new VM or contacting support")
		}
		gceAk.Close()

		attestAgent := agent.CreateAttestationAgent(rwc, client.GceAttestationKeyECC, verifierClient, principalFetcher)

		logger.Print("refreshing attestation verifier OIDC token")
		token, err := attestAgent.Attest(ctx)
		if err != nil {
			return fmt.Errorf("failed to retrieve attestation service token: %v", err)
		}

		// Get token expiration.
		claims := &jwt.RegisteredClaims{}
		_, _, err = jwt.NewParser().ParseUnverified(string(token), claims)
		if err != nil {
			return fmt.Errorf("failed to parse token: %w", err)
		}

		now := time.Now()
		if !now.Before(claims.ExpiresAt.Time) {
			return errors.New("token is expired")
		}

		// Print out the claims in the jwt payload
		mapClaims := jwt.MapClaims{}
		_, _, err = jwt.NewParser().ParseUnverified(string(token), mapClaims)
		if err != nil {
			return fmt.Errorf("failed to parse token: %w", err)
		}
		claimsString, err := json.MarshalIndent(mapClaims, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to format claims: %w", err)
		}
		logger.Println(string(claimsString))

		return nil
	},
}

// getRESTClient returns a REST verifier.Client that points to the given address.
// It defaults to the Attestation Verifier instance at
// https://confidentialcomputing.googleapis.com.
func getRESTClient(ctx context.Context, asAddr string, ProjectID string, Region string) (verifier.Client, error) {
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

func getRegion(client *metadata.Client) (string, error) {
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

func init() {
	RootCmd.AddCommand(gentokenCmd)
	addKeyFlag(gentokenCmd)
	addNonceFlag(gentokenCmd)
	addTeeNonceflag(gentokenCmd)
	addPublicKeyAlgoFlag(gentokenCmd)
	addOutputFlag(gentokenCmd)
	addTeeTechnology(gentokenCmd)
}
