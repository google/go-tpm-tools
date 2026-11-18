package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"strconv"

	"cloud.google.com/go/compute/metadata"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/proto/attest"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"
)

func newAttestCmd(o *gotpmOptions) *cobra.Command {
	var flags attestFlags
	cmd := &cobra.Command{
		Use:   "attest",
		Short: "Create a remote attestation report",
		Long: `Gather information for remote attestation.
The Attestation report contains a quote on all available PCR banks, a way to validate 
the quote, and a TCG Event Log (Linux only).
Use --key to specify the type of attestation key. It can be gceAK for GCE attestation
key or AK for a custom attestation key. By default it uses AK.
--algo flag overrides the public key algorithm for attestation key. If not provided then
by default rsa is used.
--tee-nonce attaches a 64 bytes extra data to the attestation report of TDX and SEV-SNP 
hardware and guarantees a fresh quote.
`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts, err := flags.parse()
			if err != nil {
				return err
			}

			rwc, err := o.openTPM()
			if err != nil {
				return err
			}
			defer rwc.Close()

			attestation, err := runAttest(cmd.Context(), rwc, opts)
			if err != nil {
				return err
			}

			out, err := formatAttestation(attestation, opts.format)
			if err != nil {
				return err
			}
			if opts.outputPath != "" {
				return os.WriteFile(opts.outputPath, out, 0644)
			}
			_, err = cmd.OutOrStdout().Write(out)
			return err
		},
	}
	addAttestFlags(cmd, &flags)
	cmd.AddCommand(newAttestSVSMCmd(o, &flags))
	return cmd
}

type attestKeyType string

const (
	attestKeyAK  attestKeyType = "AK"
	attestKeyGCE attestKeyType = "gceAK"
)

type outputFormat string

const (
	outputFormatBinaryPB  outputFormat = "binarypb"
	outputFormatTextproto outputFormat = "textproto"
)

type teeTech string

const (
	teeTechSEVSNP teeTech = sevSNP
	teeTechTDX    teeTech = tdx
)

func (t teeTech) createDevice() (client.TEEDevice, error) {
	switch t {
	case teeTechSEVSNP:
		device, err := client.CreateSevSnpQuoteProvider()
		if err != nil {
			return nil, fmt.Errorf("failed to create %s quote provider: %w", sevSNP, err)
		}
		return device, nil
	case teeTechTDX:
		device, err := client.CreateTdxQuoteProvider()
		if err != nil {
			return nil, fmt.Errorf("failed to create %s quote provider: %w", tdx, err)
		}
		return device, nil
	default:
		return nil, fmt.Errorf("%w: %q", errUnknownTEETechnology, t)
	}
}

type teeOptions struct {
	technology teeTech
	nonce      []byte
}

var (
	errUnknownKey           = errors.New("key should be either AK or gceAK")
	errUnsupportedKeyAlgo   = errors.New("unsupported key algorithm")
	errUnknownTEETechnology = errors.New("tee-technology should be either empty or should have values sev-snp or tdx")
	errTEENonceWithoutTech  = errors.New("use of --tee-nonce requires specifying TEE hardware type with --tee-technology")
)

type attestFlags struct {
	key           string
	keyAlgo       tpm2.Algorithm
	nonce         []byte
	teeNonce      []byte
	teeTechnology string
	format        string
	outputPath    string
}

// attestOptions configures remote attestation report generation and output.
type attestOptions struct {
	key        attestKeyType
	keyAlgo    tpm2.Algorithm
	nonce      []byte
	tee        *teeOptions
	format     outputFormat
	outputPath string
}

// addAttestFlags registers persistent flags shared by attest and attest svsm.
func addAttestFlags(cmd *cobra.Command, f *attestFlags) {
	flags := cmd.PersistentFlags()
	flags.StringVar(&f.key, "key", string(attestKeyAK), "indicates type of attestation key to use <gceAK|AK>")
	f.keyAlgo = tpm2.AlgRSA
	algo := algoFlag{
		value:   &f.keyAlgo,
		allowed: []tpm2.Algorithm{tpm2.AlgRSA, tpm2.AlgECC},
	}
	flags.Var(&algo, "algo", "public key algorithm: "+algo.Allowed())
	flags.BytesHexVar(&f.nonce, "nonce", nil, "hex encoded nonce for vTPM attestation, cannot be empty")
	// Update this description if a TEE needs a variable-length tee-nonce.
	flags.BytesHexVar(&f.teeNonce, "tee-nonce", nil, "hex encoded teenonce for hardware attestation, can be empty")
	flags.StringVar(&f.teeTechnology, "tee-technology", "", "indicates the type of TEE hardware. Should be either empty or one of sev-snp or tdx")
	flags.StringVar(&f.format, "format", string(outputFormatBinaryPB), "type of output file where attestation report stored <binarypb|textproto>")
	flags.StringVar(&f.outputPath, "output", "", "output file (defaults to stdout)")
}

func (f attestFlags) parse() (attestOptions, error) {
	key := attestKeyType(f.key)
	if key != attestKeyAK && key != attestKeyGCE {
		return attestOptions{}, fmt.Errorf("%w: %q", errUnknownKey, f.key)
	}
	if f.keyAlgo != tpm2.AlgRSA && f.keyAlgo != tpm2.AlgECC {
		return attestOptions{}, fmt.Errorf("%w: %v", errUnsupportedKeyAlgo, f.keyAlgo)
	}
	format := outputFormat(f.format)
	if format != outputFormatBinaryPB && format != outputFormatTextproto {
		return attestOptions{}, fmt.Errorf("%w: %q", errUnknownFormat, f.format)
	}
	if f.teeTechnology == "" && len(f.teeNonce) != 0 {
		return attestOptions{}, errTEENonceWithoutTech
	}
	var tee *teeOptions
	if f.teeTechnology != "" {
		tech := teeTech(f.teeTechnology)
		if tech != teeTechSEVSNP && tech != teeTechTDX {
			return attestOptions{}, fmt.Errorf("%w: %q", errUnknownTEETechnology, f.teeTechnology)
		}
		tee = &teeOptions{
			technology: tech,
			nonce:      f.teeNonce,
		}
	}
	return attestOptions{
		key:        key,
		keyAlgo:    f.keyAlgo,
		nonce:      f.nonce,
		tee:        tee,
		format:     format,
		outputPath: f.outputPath,
	}, nil
}

// runAttest generates an attestation report using the provided TPM.
func runAttest(ctx context.Context, rwc io.ReadWriter, opts attestOptions) (*attest.Attestation, error) {
	if opts.key == "" {
		opts.key = attestKeyAK
	}
	if opts.keyAlgo == tpm2.AlgUnknown {
		opts.keyAlgo = tpm2.AlgRSA
	}

	attestOpts := client.AttestOpts{
		Nonce: opts.nonce,
	}
	if opts.tee != nil {
		teeDevice, err := opts.tee.technology.createDevice()
		if err != nil {
			return nil, err
		}
		defer teeDevice.Close()
		attestOpts.TEEDevice = teeDevice
		attestOpts.TEENonce = opts.tee.nonce
	}

	attestationKey, err := createAttestationKey(rwc, opts.key, opts.keyAlgo)
	if err != nil {
		return nil, fmt.Errorf("failed to create attestation key: %w", err)
	}
	defer attestationKey.Close()

	attestOpts.TCGEventLog, err = client.GetEventLog(rwc)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve TCG Event Log: %w", err)
	}

	attestation, err := attestationKey.Attest(attestOpts)
	if err != nil {
		return nil, fmt.Errorf("failed to collect attestation report: %w", err)
	}

	if opts.key == attestKeyGCE {
		instanceInfo, err := getInstanceInfoFromMetadata(ctx)
		if err != nil {
			log.Printf("Could not get GCE instance info, continuing without it: %v", err)
		}
		attestation.InstanceInfo = instanceInfo
	}

	return attestation, nil
}

func formatAttestation(attestation *attest.Attestation, outFormat outputFormat) ([]byte, error) {
	switch outFormat {
	case outputFormatBinaryPB:
		out, err := proto.Marshal(attestation)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal attestation proto: %w", err)
		}
		return out, nil
	case outputFormatTextproto:
		return []byte(marshalOptions.Format(attestation)), nil
	default:
		return nil, fmt.Errorf("%w: %q", errUnknownFormat, outFormat)
	}
}

func createAttestationKey(rw io.ReadWriter, keyType attestKeyType, algo tpm2.Algorithm) (*client.Key, error) {
	switch keyType {
	case attestKeyAK:
		switch algo {
		case tpm2.AlgRSA:
			return client.AttestationKeyRSA(rw)
		case tpm2.AlgECC:
			return client.AttestationKeyECC(rw)
		default:
			return nil, fmt.Errorf("%w: %v", errUnsupportedKeyAlgo, algo)
		}
	case attestKeyGCE:
		switch algo {
		case tpm2.AlgRSA:
			return client.GceAttestationKeyRSA(rw)
		case tpm2.AlgECC:
			return client.GceAttestationKeyECC(rw)
		default:
			return nil, fmt.Errorf("%w: %v", errUnsupportedKeyAlgo, algo)
		}
	default:
		return nil, fmt.Errorf("%w: %q", errUnknownKey, keyType)
	}
}

func getInstanceInfoFromMetadata(ctx context.Context) (*attest.GCEInstanceInfo, error) {
	var err error
	instanceInfo := &attest.GCEInstanceInfo{}

	instanceInfo.ProjectId, err = metadata.ProjectIDWithContext(ctx)
	if err != nil {
		return nil, err
	}

	projectNumber, err := metadata.NumericProjectIDWithContext(ctx)
	if err != nil {
		return nil, err
	}
	instanceInfo.ProjectNumber, err = strconv.ParseUint(projectNumber, 10, 64)
	if err != nil {
		return nil, err
	}

	instanceInfo.Zone, err = metadata.ZoneWithContext(ctx)
	if err != nil {
		return nil, err
	}

	instanceID, err := metadata.InstanceIDWithContext(ctx)
	if err != nil {
		return nil, err
	}
	instanceInfo.InstanceId, err = strconv.ParseUint(instanceID, 10, 64)
	if err != nil {
		return nil, err
	}

	instanceInfo.InstanceName, err = metadata.InstanceNameWithContext(ctx)
	if err != nil {
		return nil, err
	}

	return instanceInfo, err
}
