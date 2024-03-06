package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"time"

	"cloud.google.com/go/compute/metadata"
	"cloud.google.com/go/logging"
	"github.com/containerd/containerd/namespaces"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/launcher/agent"
	"github.com/google/go-tpm-tools/launcher/spec"
	"github.com/google/go-tpm-tools/launcher/verifier"
	"github.com/google/go-tpm-tools/launcher/verifier/rest"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var mdsClient *metadata.Client
var mockCloudLoggingServerAddress string

const toolName = "gotpm"

// If hardware technology needs a variable length teenonce then please modify the flags description
var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Attest and fetch an OIDC token from Google Attestation Verification Service.",
	Long: `Gather attestation report and send it to Google Attestation Verification Service for an OIDC token.
The OIDC token includes claims regarding the GCE VM, which is verified by Attestation Verification Service. Note that Confidential Computing API needs to be enabled for your account to access Google Attestation Verification Service https://pantheon.corp.google.com/apis/api/confidentialcomputing.googleapis.com.
--algo flag overrides the public key algorithm for the GCE TPM attestation key. If not provided then by default rsa is used.
`,
	Args: cobra.NoArgs,
	RunE: func(*cobra.Command, []string) error {
		rwc, err := openTpm()
		if err != nil {
			return err
		}
		defer rwc.Close()

		// Metadata Server (MDS). A GCP specific client.
		mdsClient = metadata.NewClient(nil)

		ctx := namespaces.WithNamespace(context.Background(), namespaces.Default)
		// TODO: principalFetcher is copied from go-tpm-tools/launcher/container_runner.go, to be refactored
		// Fetch GCP specific ID token with specific audience.
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
			fmt.Fprintf(debugOutput(), "GCP ID token fetched is: %s\n", idToken)
			tokens := [][]byte{[]byte(idToken)}
			return tokens, nil
		}

		fmt.Fprintf(debugOutput(), "Attestation Address is set to %s\n", asAddress)

		region, err := getRegion(mdsClient)
		if err != nil {
			return fmt.Errorf("failed to fetch Region from MDS, the tool is probably not running in a GCE VM: %v", err)
		}

		projectID, err := mdsClient.ProjectID()
		if err != nil {
			return fmt.Errorf("failed to retrieve ProjectID from MDS: %v", err)
		}

		verifierClient, err := getRESTClient(ctx, asAddress, projectID, region)
		if err != nil {
			return fmt.Errorf("failed to create REST verifier client: %v", err)
		}

		// Supports GCE VM. Hard code the AK type. Set GCE AK (EK signing) cert
		var gceAK *client.Key
		var usedKeyAlgo string
		if keyAlgo == tpm2.AlgRSA {
			usedKeyAlgo = "RSA"
			gceAK, err = client.GceAttestationKeyRSA(rwc)
		}
		if keyAlgo == tpm2.AlgECC {
			usedKeyAlgo = "ECC"
			gceAK, err = client.GceAttestationKeyECC(rwc)
		}
		if err != nil {
			return err
		}
		if gceAK.Cert() == nil {
			return errors.New("failed to find gceAKCert on this VM: try creating a new VM or verifying the VM has an EK cert using get-shielded-identity gcloud command. The used key algorithm is: " + usedKeyAlgo)
		}
		gceAK.Close()

		var cloudLogClient *logging.Client
		var cloudLogger *logging.Logger
		if cloudLog {
			if audience == "" {
				return errors.New("cloud logging requires the --audience flag")
			}
			if mockCloudLoggingServerAddress != "" {
				conn, err := grpc.Dial(mockCloudLoggingServerAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
				if err != nil {
					log.Fatalf("dialing %q: %v", mockCloudLoggingServerAddress, err)
				}
				cloudLogClient, err = logging.NewClient(ctx, TestProjectID, option.WithGRPCConn(conn))
				if err != nil {
					return fmt.Errorf("failed to create cloud logging client for mock cloud logging server: %w", err)
				}
			} else {
				cloudLogClient, err = logging.NewClient(ctx, projectID)
				if err != nil {
					return fmt.Errorf("failed to create cloud logging client: %w", err)
				}
			}

			cloudLogger = cloudLogClient.Logger(toolName)
			fmt.Fprintf(debugOutput(), "cloudLogger created for project: "+projectID+"\n")
		}

		key = "gceAK"
		attestAgent := agent.CreateAttestationAgent(rwc, attestationKeys[key][keyAlgo], verifierClient, principalFetcher, nil, spec.LaunchSpec{}, nil, cloudLogger)

		fmt.Fprintf(debugOutput(), "Fetching attestation verifier OIDC token\n")
		token, err := attestAgent.Attest(ctx, agent.AttestAgentOpts{Aud: audience, TokenType: "OIDC"})
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

		if output == "" {
			fmt.Fprintf(messageOutput(), string(token)+"\n")
		} else {
			out := []byte(token)
			if _, err := dataOutput().Write(out); err != nil {
				return fmt.Errorf("failed to write the token: %v", err)
			}
		}

		if cloudLog {
			cloudLogger.Log(logging.Entry{Payload: map[string]string{"token": string(token)}})
			cloudLogger.Log(logging.Entry{Payload: mapClaims})
			cloudLogClient.Close()
			if err != nil {
				return fmt.Errorf("failed to close cloud logging client: %w", err)
			}
		}

		fmt.Fprintf(debugOutput(), string(claimsString)+"\n"+"Note: these Claims are for debugging purpose and not verified"+"\n")

		return nil
	},
}

// TODO: getRESTClient is copied from go-tpm-tools/launcher/container_runner.go, to be refactored.
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
	RootCmd.AddCommand(tokenCmd)
	addOutputFlag(tokenCmd)
	addPublicKeyAlgoFlag(tokenCmd)
	addAsAddressFlag(tokenCmd)
	addCloudLoggingFlag(tokenCmd)
	addAudienceFlag(tokenCmd)
	// TODO: Add TEE hardware OIDC token generation
	// addTeeNonceflag(tokenCmd)
	// addTeeTechnology(tokenCmd)
}
