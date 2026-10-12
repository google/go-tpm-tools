package cmd

import (
	"context"
	_ "crypto/sha512" // Ensure SHA384 is available
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"cloud.google.com/go/compute/metadata"
	"cloud.google.com/go/logging"
	"github.com/golang-jwt/jwt/v4"
	tabi "github.com/google/go-tdx-guest/abi"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/internal"
	"github.com/google/go-tpm-tools/verifier"
	"github.com/google/go-tpm-tools/verifier/models"
	"github.com/google/go-tpm-tools/verifier/util"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/spf13/cobra"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/option"
)

const toolName = "gotpm"

func getTEEDeviceFromTech(tech string) (client.TEEDevice, error) {
	switch tech {
	case sevSNP:
		device, err := client.CreateSevSnpQuoteProvider()
		if err != nil {
			return nil, fmt.Errorf("failed to create %s quote provider: %w", sevSNP, err)
		}
		return device, nil
	case tdx:
		device, err := client.CreateTdxQuoteProvider()
		if err != nil {
			return nil, fmt.Errorf("failed to create %s quote provider: %w", tdx, err)
		}
		return device, nil
	case "":
		return nil, nil
	default:
		return nil, fmt.Errorf("tee-technology should be either empty or should have values %s or %s", sevSNP, tdx)
	}
}

// TokenOptions contains the parameters for generating an attestation claims token.
type TokenOptions struct {
	Audience         string
	CustomNonces     []string
	KeyAlgo          tpm2.Algorithm
	VerifierEndpoint string
	EventLog         []byte
	OutputPath       string
	CloudLog         bool
	TEETechnology    string
	MDSClient        *metadata.Client
	HTTPClient       *http.Client
	CloudLogClient   *logging.Client
}

func parseTokenFlags(cmd *cobra.Command) (TokenOptions, error) {
	flags := cmd.Flags()
	opts := TokenOptions{}

	var err error
	if flags.Changed("verifier-endpoint") {
		opts.VerifierEndpoint, err = flags.GetString("verifier-endpoint")
		if err != nil {
			return TokenOptions{}, err
		}
	}
	if flags.Changed("audience") {
		opts.Audience, err = flags.GetString("audience")
		if err != nil {
			return TokenOptions{}, err
		}
	}
	if flags.Changed("custom-nonce") {
		opts.CustomNonces, err = flags.GetStringArray("custom-nonce")
		if err != nil {
			return TokenOptions{}, err
		}
	}
	if flags.Changed("cloud-log") {
		opts.CloudLog, err = flags.GetBool("cloud-log")
		if err != nil {
			return TokenOptions{}, err
		}
	}
	if flags.Changed("tee-technology") {
		opts.TEETechnology, err = flags.GetString("tee-technology")
		if err != nil {
			return TokenOptions{}, err
		}
	}
	if flags.Changed("output") {
		opts.OutputPath, err = flags.GetString("output")
		if err != nil {
			return TokenOptions{}, err
		}
	}

	if flags.Changed("algo") {
		if f := flags.Lookup("algo"); f != nil && f.Value.String() != "" {
			switch val := f.Value.String(); val {
			case "rsa":
				opts.KeyAlgo = tpm2.AlgRSA
			case "ecc":
				opts.KeyAlgo = tpm2.AlgECC
			default:
				return TokenOptions{}, fmt.Errorf("unsupported key algorithm: %q", val)
			}
		}
	} else {
		opts.KeyAlgo = tpm2.AlgRSA
	}

	if flags.Changed("event-log") {
		eventLogPath, err := flags.GetString("event-log")
		if err != nil {
			return TokenOptions{}, err
		}
		data, err := os.ReadFile(eventLogPath)
		if err != nil {
			return TokenOptions{}, fmt.Errorf("reading event log: %w", err)
		}
		opts.EventLog = data
	}

	return opts, nil
}

// If hardware technology needs a variable length teenonce then please modify the flags description
var tokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Attest and fetch an OIDC token from Google Attestation Verification Service.",
	Long: `Gather attestation report and send it to Google Attestation Verification Service for an OIDC token.
The OIDC token includes claims regarding the GCE VM, which is verified by Attestation Verification Service. Note that Confidential Computing API needs to be enabled for your account to access Google Attestation Verification Service https://console.cloud.google.com/apis/api/confidentialcomputing.googleapis.com.
--algo flag overrides the public key algorithm for the GCE TPM attestation key. If not provided then by default rsa is used.
`,
	Args: cobra.NoArgs,
	RunE: func(cmd *cobra.Command, args []string) error {
		_ = args
		opts, err := parseTokenFlags(cmd)
		if err != nil {
			return err
		}

		rwc, err := openTpm()
		if err != nil {
			return err
		}
		defer rwc.Close()

		token, err := RunToken(cmd.Context(), rwc, opts)
		if err != nil {
			return err
		}

		if opts.OutputPath == "" {
			fmt.Fprintf(messageOutput(), "%s\n", token)
			return nil
		}
		if err := os.WriteFile(opts.OutputPath, token, 0644); err != nil {
			return fmt.Errorf("failed to write token: %w", err)
		}
		return nil
	},
}

// RunToken retrieves an OIDC claims token from the verification service using the provided TPM.
func RunToken(ctx context.Context, rwc io.ReadWriter, opts TokenOptions) ([]byte, error) {
	if opts.VerifierEndpoint == "" {
		opts.VerifierEndpoint = "https://confidentialcomputing.googleapis.com"
	}
	if opts.KeyAlgo == 0 {
		opts.KeyAlgo = tpm2.AlgRSA
	}
	if opts.MDSClient == nil {
		opts.MDSClient = metadata.NewClient(nil)
	}
	if opts.HTTPClient == nil {
		var err error
		opts.HTTPClient, err = google.DefaultClient(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP client: %w", err)
		}
	}

	fmt.Fprintf(debugOutput(), "Attestation Address is set to %s\n", opts.VerifierEndpoint)

	region, err := util.GetRegion(opts.MDSClient)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch Region from MDS, the tool is probably not running in a GCE VM: %w", err)
	}

	projectID, err := opts.MDSClient.ProjectIDWithContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve ProjectID from MDS: %w", err)
	}

	verifierClient, err := util.NewRESTClient(ctx, opts.VerifierEndpoint, projectID, region, option.WithHTTPClient(opts.HTTPClient))
	if err != nil {
		return nil, fmt.Errorf("failed to create REST verifier client: %w", err)
	}

	createAK, ok := attestationKeys["gceAK"][opts.KeyAlgo]
	if !ok {
		return nil, fmt.Errorf("unsupported key algorithm: %v", opts.KeyAlgo)
	}
	ak, err := createAK(rwc)
	if err != nil {
		return nil, fmt.Errorf("failed to get an AK: %w", err)
	}
	defer ak.Close()
	if ak.Cert() == nil {
		return nil, fmt.Errorf("failed to find GCE AK Certificate on this VM: try creating a new VM or verifying the VM has an EK cert using get-shielded-identity gcloud command. The used key algorithm is: %v", opts.KeyAlgo)
	}

	var cloudLogger *logging.Logger
	if opts.CloudLog {
		if opts.Audience == "" {
			return nil, errors.New("cloud logging requires the --audience flag")
		}
		if opts.CloudLogClient != nil {
			cloudLogger = opts.CloudLogClient.Logger(toolName)
		} else {
			cloudLogClient, err := logging.NewClient(ctx, projectID)
			if err != nil {
				return nil, fmt.Errorf("failed to create cloud logging client: %w", err)
			}
			defer cloudLogClient.Close()
			cloudLogger = cloudLogClient.Logger(toolName)
		}
		fmt.Fprintf(debugOutput(), "cloudLogger created for project: %s\n", projectID)
	}

	fmt.Fprint(debugOutput(), "Fetching attestation verifier OIDC token\n")

	challenge, err := verifierClient.CreateChallenge(ctx)
	if err != nil {
		return nil, err
	}

	principalTokens, err := util.PrincipalFetcher(challenge.Name, opts.MDSClient)
	if err != nil {
		return nil, fmt.Errorf("failed to get principal tokens: %w", err)
	}

	attestOpts := client.AttestOpts{
		Nonce:            challenge.Nonce,
		CertChainFetcher: http.DefaultClient,
	}

	attestOpts.TEEDevice, err = getTEEDeviceFromTech(opts.TEETechnology)
	if err != nil {
		return nil, err
	}
	if attestOpts.TEEDevice != nil {
		defer attestOpts.TEEDevice.Close()
	}

	if opts.EventLog != nil {
		attestOpts.TCGEventLog = opts.EventLog
	}

	attestation, err := ak.Attest(attestOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to attest: %w", err)
	}

	req := verifier.VerifyAttestationRequest{
		Challenge:      challenge,
		GcpCredentials: principalTokens,
		Attestation:    attestation,
		TokenOptions:   &models.TokenOptions{Audience: opts.Audience, Nonces: opts.CustomNonces, TokenType: "OIDC"},
	}

	if opts.TEETechnology == tdx {
		if attestation.GetTdxAttestation() != nil {
			fmt.Fprintln(debugOutput(), "Using Explicit TDCCELAttestation Path (ACPI tables)")

			zone, err := opts.MDSClient.ZoneWithContext(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to fetch zone from MDS: %w", err)
			}

			projectNumber, err := opts.MDSClient.NumericProjectIDWithContext(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve project number from MDS: %w", err)
			}

			instanceID, err := opts.MDSClient.InstanceIDWithContext(ctx)
			if err != nil {
				return nil, fmt.Errorf("failed to retrieve instance ID from MDS: %w", err)
			}

			req.GCEInstance = fmt.Sprintf("projects/%s/zones/%s/instances/%s", projectNumber, zone, instanceID)

			rawQuote, err := tabi.QuoteToAbiBytes(attestation.GetTdxAttestation())
			if err != nil {
				return nil, fmt.Errorf("failed to convert TDX quote to bytes: %w", err)
			}

			ccelTable, err := os.ReadFile(internal.ACPITableFile)
			if err != nil {
				fmt.Fprintf(debugOutput(), "Could not read CCEL ACPI table: %v\n", err)
			}

			ccelData, err := os.ReadFile(internal.CCELEventLogFile)
			if err != nil {
				fmt.Fprintf(debugOutput(), "Could not read CCEL event log: %v\n", err)
			}

			req.TDCCELAttestation = &verifier.TDCCELAttestation{
				TdQuote:       rawQuote,
				CcelAcpiTable: ccelTable,
				CcelData:      ccelData,
			}
			req.Attestation = nil
		}
	}

	resp, err := verifierClient.VerifyAttestation(ctx, req)
	if err != nil {
		return nil, err
	}
	if len(resp.PartialErrs) > 0 {
		fmt.Fprintf(debugOutput(), "partial errors from VerifyAttestation: %v", resp.PartialErrs)
	}

	token := resp.ClaimsToken

	claims := &jwt.RegisteredClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(string(token), claims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}

	now := time.Now()
	if !now.Before(claims.ExpiresAt.Time) {
		return nil, errors.New("token is expired")
	}

	mapClaims := jwt.MapClaims{}
	_, _, err = jwt.NewParser().ParseUnverified(string(token), mapClaims)
	if err != nil {
		return nil, fmt.Errorf("failed to parse token: %w", err)
	}
	claimsString, err := json.MarshalIndent(mapClaims, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to format claims: %w", err)
	}

	if opts.CloudLog {
		cloudLogger.Log(logging.Entry{Payload: challenge})
		cloudLogger.Log(logging.Entry{Payload: attestation})
		cloudLogger.Log(logging.Entry{Payload: map[string]string{"token": string(token)}})
		cloudLogger.Log(logging.Entry{Payload: mapClaims})
	}

	fmt.Fprintf(debugOutput(), "%s\nNote: these Claims are for debugging purpose and not verified\n", claimsString)
	return token, nil
}

func init() {
	RootCmd.AddCommand(tokenCmd)
	addOutputFlag(tokenCmd)
	addPublicKeyAlgoFlag(tokenCmd)
	tokenCmd.Flags().String("verifier-endpoint", "https://confidentialcomputing.googleapis.com",
		"the attestation verifier endpoint used to retrieve an attestation claims token")
	tokenCmd.Flags().Bool("cloud-log", false,
		"logs the attestation and token to Cloud Logging for auditing purposes. Requires the audience flag.")
	tokenCmd.Flags().String("audience", "",
		"the audience field in the claims token. Cannot be sts.googleapis.com.")
	tokenCmd.Flags().StringArray("custom-nonce", nil,
		"the custom nonce field in the claims token. use this flag multiple times to add multiple custom nonces.")
	addEventLogFlag(tokenCmd)
	// TODO: Add TEE hardware OIDC token generation
	// addTeeNonceflag(tokenCmd)
	addTeeTechnology(tokenCmd)
}
