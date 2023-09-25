package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"cloud.google.com/go/compute/metadata"
	"github.com/containerd/containerd/namespaces"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/launcher/agent"
	"github.com/google/go-tpm-tools/launcher/verifier"
	"github.com/google/go-tpm-tools/launcher/verifier/rest"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

var mdsClient *metadata.Client

// If hardware technology needs a variable length teenonce then please modify the flags description
var gentokenCmd = &cobra.Command{
	Use:   "gentoken",
	Short: "Attest and fetch an OIDC token from Google Attestation Verification Service.",
	Long: `Gather attestation report and send it to Google Attestation Verification Service for an OIDC token.
The OIDC token includes claims regarding the authentication of the user by the authorization server (Google IAM server) with the use of an OAuth client application(Google Cloud apps). Note that this command will only work on a GCE VM with confidential space image for now. And Confidential computing API needs to be enabled for your account to access Google Attestation Verification Service https://pantheon.corp.google.com/apis/api/confidentialcomputing.googleapis.com.
--algo flag overrides the public key algorithm for attestation key. If not provided then by default rsa is used.
`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {

		rwc, err := openTpm()
		if err != nil {
			return err
		}
		defer rwc.Close()

		// Metadata Server (MDS). A GCP specific client.
		mdsClient = metadata.NewClient(nil)

		ctx := namespaces.WithNamespace(context.Background(), namespaces.Default)
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
			fmt.Fprintf(debugOutput(), "GCP ID token fetched is: %s\n", idToken)
			if err != nil {
				return nil, fmt.Errorf("failed to get principal tokens: %w", err)
			}

			tokens := [][]byte{[]byte(idToken)}
			return tokens, nil
		}

		if asAddress == "" {
			asAddress = "https://confidentialcomputing.googleapis.com"
		}
		fmt.Fprintf(debugOutput(), "Attestation Address is set to %s\n", asAddress)

		Region, err := getRegion(mdsClient)
		if err != nil {
			return fmt.Errorf("failed to fetch Region from MDS: %v", err)
		}

		ProjectID, err := mdsClient.ProjectID()
		if err != nil {
			return fmt.Errorf("failed to retrieve ProjectID from MDS: %v", err)
		}

		verifierClient, err := getRESTClient(ctx, asAddress, ProjectID, Region)
		if err != nil {
			return fmt.Errorf("failed to create REST verifier client: %v", err)
		}

		//  supports GCE VM. Hard code the AK type.
		key = "gceAK"
		fmt.Fprintf(debugOutput(), "key is set to gceAK\n")

		// Set GCE AK (EK signing) cert
		if key == "gceAK" {
			var gceAK *client.Key
			var err error
			if keyAlgo == tpm2.AlgRSA {
				gceAK, err = client.GceAttestationKeyRSA(rwc)
			}
			if keyAlgo == tpm2.AlgECC {
				gceAK, err = client.GceAttestationKeyECC(rwc)
			}
			if err != nil {
				return err
			}
			if gceAK.Cert() == nil {
				return errors.New("failed to find gceAKCert on this VM: try creating a new VM or contacting support")
			}
			gceAK.Close()
		}

		attestAgent := agent.CreateAttestationAgent(rwc, attestationKeys[key][keyAlgo], verifierClient, principalFetcher)

		fmt.Fprintf(debugOutput(), "Fetching attestation verifier OIDC token\n")
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

		fmt.Fprintf(debugOutput(), string(claimsString)+"\n")

		if output == "" {
			fmt.Fprintf(messageOutput(), string(token)+"\n")
		}

		if output != "" {
			out := []byte(token)
			if _, err := dataOutput().Write(out); err != nil {
				return fmt.Errorf("failed to write attestation report: %v", err)
			}
		}

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
	addOutputFlag(gentokenCmd)
	addPublicKeyAlgoFlag(gentokenCmd)
	addAsAdressFlag(gentokenCmd)
	// TODO: Add TEE hardware OIDC token generation
	// addTeeNonceflag(gentokenCmd)
	// addTeeTechnology(gentokenCmd)
}
