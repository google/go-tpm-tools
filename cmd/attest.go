package cmd

import (
	"context"
	"encoding/hex"
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

			out, err := formatProto(attestation, opts.format)
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

type attestKeyType int

const (
	attestKeyAK attestKeyType = iota
	attestKeyGCE
)

func parseAttestKey(s string) (attestKeyType, error) {
	switch s {
	case "AK":
		return attestKeyAK, nil
	case "gceAK":
		return attestKeyGCE, nil
	default:
		return 0, fmt.Errorf("%w: %q", errUnknownKey, s)
	}
}

func (k attestKeyType) String() string {
	switch k {
	case attestKeyAK:
		return "AK"
	case attestKeyGCE:
		return "gceAK"
	default:
		return fmt.Sprintf("attestKeyType(%d)", k)
	}
}

type attestKeyAlgo int

const (
	attestKeyAlgoRSA attestKeyAlgo = iota
	attestKeyAlgoECC
)

func parseAttestKeyAlgo(s string) (attestKeyAlgo, error) {
	switch s {
	case "rsa":
		return attestKeyAlgoRSA, nil
	case "ecc":
		return attestKeyAlgoECC, nil
	default:
		return 0, fmt.Errorf("%w: %q", errUnsupportedKeyAlgo, s)
	}
}

func attestKeyAlgoFromTPM2(algo tpm2.Algorithm) (attestKeyAlgo, error) {
	switch algo {
	case tpm2.AlgRSA:
		return attestKeyAlgoRSA, nil
	case tpm2.AlgECC:
		return attestKeyAlgoECC, nil
	default:
		return 0, fmt.Errorf("%w: %v", errUnsupportedKeyAlgo, algo)
	}
}

func (a attestKeyAlgo) String() string {
	switch a {
	case attestKeyAlgoRSA:
		return "rsa"
	case attestKeyAlgoECC:
		return "ecc"
	default:
		return fmt.Sprintf("attestKeyAlgo(%d)", a)
	}
}

type outputFormat int

const (
	outputFormatBinaryPB outputFormat = iota
	outputFormatTextproto
)

func parseOutputFormat(s string) (outputFormat, error) {
	switch s {
	case "binarypb":
		return outputFormatBinaryPB, nil
	case "textproto":
		return outputFormatTextproto, nil
	default:
		return 0, fmt.Errorf("%w: %q", errUnknownFormat, s)
	}
}

func (f outputFormat) String() string {
	switch f {
	case outputFormatBinaryPB:
		return "binarypb"
	case outputFormatTextproto:
		return "textproto"
	default:
		return fmt.Sprintf("outputFormat(%d)", f)
	}
}

type teeTech int

const (
	teeTechSEVSNP teeTech = iota
	teeTechTDX
)

func parseTEETech(s string) (teeTech, error) {
	switch s {
	case sevSNP:
		return teeTechSEVSNP, nil
	case tdx:
		return teeTechTDX, nil
	default:
		return 0, fmt.Errorf("%w: %q", errUnknownTEETechnology, s)
	}
}

func (t teeTech) String() string {
	switch t {
	case teeTechSEVSNP:
		return sevSNP
	case teeTechTDX:
		return tdx
	default:
		return fmt.Sprintf("teeTech(%d)", t)
	}
}

type teeOptions struct {
	technology teeTech
	nonce      []byte
}

var (
	errUnknownKey           = errors.New("key should be either AK or gceAK")
	errUnsupportedKeyAlgo   = errors.New("unsupported key algorithm")
	errEmptyNonce           = errors.New("nonce cannot be empty")
	errUnknownTEETechnology = errors.New("tee-technology should be either empty or should have values sev-snp or tdx")
	errTEENonceWithoutTech  = errors.New("use of --tee-nonce requires specifying TEE hardware type with --tee-technology")
)

type attestFlags struct {
	key           string
	keyAlgo       string
	nonce         string
	teeNonce      string
	teeTechnology string
	format        string
	outputPath    string
}

// attestOptions configures remote attestation report generation and output.
type attestOptions struct {
	key        attestKeyType
	keyAlgo    attestKeyAlgo
	nonce      []byte
	tee        *teeOptions
	format     outputFormat
	outputPath string
}

// addAttestFlags registers persistent flags shared by attest and attest svsm.
func addAttestFlags(cmd *cobra.Command, f *attestFlags) {
	flags := cmd.PersistentFlags()
	flags.StringVar(&f.key, "key", "AK", "indicates type of attestation key to use <gceAK|AK>")
	flags.StringVar(&f.keyAlgo, "algo", "rsa", "public key algorithm: rsa, ecc")
	flags.StringVar(&f.nonce, "nonce", "", "hex encoded nonce for vTPM attestation, cannot be empty")
	// Update this description if a TEE needs a variable-length tee-nonce.
	flags.StringVar(&f.teeNonce, "tee-nonce", "", "hex encoded teenonce for hardware attestation, can be empty")
	flags.StringVar(&f.teeTechnology, "tee-technology", "", "indicates the type of TEE hardware. Should be either empty or one of sev-snp or tdx")
	flags.StringVar(&f.format, "format", "binarypb", "type of output file where attestation report stored <binarypb|textproto>")
	flags.StringVar(&f.outputPath, "output", "", "output file (defaults to stdout)")
}

func (f attestFlags) parse() (attestOptions, error) {
	key, err := parseAttestKey(f.key)
	if err != nil {
		return attestOptions{}, err
	}
	keyAlgo, err := parseAttestKeyAlgo(f.keyAlgo)
	if err != nil {
		return attestOptions{}, err
	}
	format, err := parseOutputFormat(f.format)
	if err != nil {
		return attestOptions{}, err
	}
	nonce, err := hex.DecodeString(f.nonce)
	if err != nil {
		return attestOptions{}, fmt.Errorf("invalid --nonce %q: %w", f.nonce, err)
	}
	if len(nonce) == 0 {
		return attestOptions{}, errEmptyNonce
	}
	var teeNonce []byte
	if f.teeNonce != "" {
		teeNonce, err = hex.DecodeString(f.teeNonce)
		if err != nil {
			return attestOptions{}, fmt.Errorf("invalid --tee-nonce %q: %w", f.teeNonce, err)
		}
	}
	if f.teeTechnology == "" && len(teeNonce) != 0 {
		return attestOptions{}, errTEENonceWithoutTech
	}
	var tee *teeOptions
	if f.teeTechnology != "" {
		tech, err := parseTEETech(f.teeTechnology)
		if err != nil {
			return attestOptions{}, err
		}
		tee = &teeOptions{
			technology: tech,
			nonce:      teeNonce,
		}
	}
	return attestOptions{
		key:        key,
		keyAlgo:    keyAlgo,
		nonce:      nonce,
		tee:        tee,
		format:     format,
		outputPath: f.outputPath,
	}, nil
}

// runAttest generates an attestation report using the provided TPM.
func runAttest(ctx context.Context, rwc io.ReadWriter, opts attestOptions) (*attest.Attestation, error) {
	if len(opts.nonce) == 0 {
		return nil, errEmptyNonce
	}

	attestOpts := client.AttestOpts{
		Nonce: opts.nonce,
	}
	if opts.tee != nil {
		teeDevice, err := createTEEDevice(opts.tee.technology)
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

func formatProto(message proto.Message, outFormat outputFormat) ([]byte, error) {
	switch outFormat {
	case outputFormatBinaryPB:
		out, err := proto.Marshal(message)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal attestation proto: %w", err)
		}
		return out, nil
	case outputFormatTextproto:
		return []byte(marshalOptions.Format(message)), nil
	default:
		return nil, fmt.Errorf("%w: %v", errUnknownFormat, outFormat)
	}
}

func createAttestationKey(rw io.ReadWriter, keyType attestKeyType, algo attestKeyAlgo) (*client.Key, error) {
	switch keyType {
	case attestKeyAK:
		switch algo {
		case attestKeyAlgoRSA:
			return client.AttestationKeyRSA(rw)
		case attestKeyAlgoECC:
			return client.AttestationKeyECC(rw)
		default:
			return nil, fmt.Errorf("%w: %v", errUnsupportedKeyAlgo, algo)
		}
	case attestKeyGCE:
		switch algo {
		case attestKeyAlgoRSA:
			return client.GceAttestationKeyRSA(rw)
		case attestKeyAlgoECC:
			return client.GceAttestationKeyECC(rw)
		default:
			return nil, fmt.Errorf("%w: %v", errUnsupportedKeyAlgo, algo)
		}
	default:
		return nil, fmt.Errorf("%w: %v", errUnknownKey, keyType)
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
