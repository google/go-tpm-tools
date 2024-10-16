package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"cloud.google.com/go/compute/metadata"
	"cloud.google.com/go/logging"
	"github.com/containerd/containerd/namespaces"
	"github.com/golang-jwt/jwt/v4"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/verifier"
	"github.com/google/go-tpm-tools/verifier/util"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/spf13/cobra"
	"google.golang.org/api/option"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var mockCloudLoggingServerAddress string

const toolName = "gotpm"

// If hardware technology needs a variable length teenonce then please modify the flags description
var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Attest and fetch an OIDC token from Google Attestation Verification Service.",
	Long: `Gather attestation report and send it to Google Attestation Verification Service for an OIDC token.
The OIDC token includes claims regarding the GCE VM, which is verified by Attestation Verification Service. Note that Confidential Computing API needs to be enabled for your account to access Google Attestation Verification Service https://console.cloud.google.com/apis/api/confidentialcomputing.googleapis.com.
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
		mdsClient := metadata.NewClient(nil)

		ctx := namespaces.WithNamespace(context.Background(), namespaces.Default)

		fmt.Fprintf(debugOutput(), "Attestation Address is set to %s\n", asAddress)

		region, err := util.GetRegion(mdsClient)
		if err != nil {
			return fmt.Errorf("failed to fetch Region from MDS, the tool is probably not running in a GCE VM: %v", err)
		}

		projectID, err := mdsClient.ProjectIDWithContext(ctx)
		if err != nil {
			return fmt.Errorf("failed to retrieve ProjectID from MDS: %v", err)
		}

		verifierClient, err := util.NewRESTClient(ctx, asAddress, projectID, region)
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
			return errors.New("failed to find GCE AK Certificate on this VM: try creating a new VM or verifying the VM has an EK cert using get-shielded-identity gcloud command. The used key algorithm is: " + usedKeyAlgo)
		}
		gceAK.Close()

		var cloudLogClient *logging.Client
		var cloudLogger *logging.Logger
		if cloudLog {
			if audience == "" {
				return errors.New("cloud logging requires the --audience flag")
			}
			if mockCloudLoggingServerAddress != "" {
				conn, err := grpc.NewClient(mockCloudLoggingServerAddress, grpc.WithTransportCredentials(insecure.NewCredentials()))
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
			fmt.Fprintf(debugOutput(), "cloudLogger created for project: %s\n", projectID)
		}

		key = "gceAK"

		fmt.Fprint(debugOutput(), "Fetching attestation verifier OIDC token\n")

		challenge, err := verifierClient.CreateChallenge(ctx)
		if err != nil {
			return err
		}

		principalTokens, err := util.PrincipalFetcher(challenge.Name, mdsClient)
		if err != nil {
			return fmt.Errorf("failed to get principal tokens: %w", err)
		}

		ak, err := attestationKeys[key][keyAlgo](rwc)
		if err != nil {
			return fmt.Errorf("failed to get an AK: %w", err)
		}
		attestation, err := ak.Attest(client.AttestOpts{Nonce: challenge.Nonce, CertChainFetcher: http.DefaultClient})
		if err != nil {
			return fmt.Errorf("failed to attest: %v", err)
		}
		ak.Close()

		req := verifier.VerifyAttestationRequest{
			Challenge:      challenge,
			GcpCredentials: principalTokens,
			Attestation:    attestation,
			TokenOptions:   verifier.TokenOptions{CustomAudience: audience, CustomNonce: customNonce, TokenType: "OIDC"},
		}

		resp, err := verifierClient.VerifyAttestation(ctx, req)
		if err != nil {
			return err
		}
		if len(resp.PartialErrs) > 0 {
			fmt.Fprintf(debugOutput(), "partial errors from VerifyAttestation: %v", resp.PartialErrs)
		}

		token := resp.ClaimsToken

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
			fmt.Fprintf(messageOutput(), "%s\n", string(token))
		} else {
			out := []byte(token)
			if _, err := dataOutput().Write(out); err != nil {
				return fmt.Errorf("failed to write the token: %v", err)
			}
		}

		if cloudLog {
			cloudLogger.Log(logging.Entry{Payload: challenge})
			cloudLogger.Log(logging.Entry{Payload: attestation})
			cloudLogger.Log(logging.Entry{Payload: map[string]string{"token": string(token)}})
			cloudLogger.Log(logging.Entry{Payload: mapClaims})
			cloudLogClient.Close()
			if err != nil {
				return fmt.Errorf("failed to close cloud logging client: %w", err)
			}
		}

		fmt.Fprintf(debugOutput(), "%s\nNote: these Claims are for debugging purpose and not verified\n", string(claimsString))

		return nil
	},
}

func init() {
	RootCmd.AddCommand(tokenCmd)
	addOutputFlag(tokenCmd)
	addPublicKeyAlgoFlag(tokenCmd)
	addAsAddressFlag(tokenCmd)
	addCloudLoggingFlag(tokenCmd)
	addAudienceFlag(tokenCmd)
	addEventLogFlag(tokenCmd)
	addCustomNonceFlag(tokenCmd)
	// TODO: Add TEE hardware OIDC token generation
	// addTeeNonceflag(tokenCmd)
	// addTeeTechnology(tokenCmd)
}
