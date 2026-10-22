package cmd

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/spf13/cobra"
	"google.golang.org/protobuf/proto"
)

// Add constants for other devices when required
const (
	// sevSNP is a constant denotes device name for teeTechnology
	sevSNP = "sev-snp"
	// tdx is a constant denotes device name for teeTechnology
	tdx = "tdx"
)

type pcrsFlag struct {
	value *[]int
}

func (f *pcrsFlag) Set(val string) error {
	for _, d := range strings.Split(val, ",") {
		pcr, err := strconv.Atoi(d)
		if err != nil {
			return err
		}
		if pcr < 0 || pcr >= client.NumPCRs {
			return errors.New("pcr out of range")
		}
		*f.value = append(*f.value, pcr)
	}
	return nil
}

func (f *pcrsFlag) Type() string {
	return "pcrs"
}

func (f *pcrsFlag) String() string {
	if len(*f.value) == 0 {
		return ""
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d", (*f.value)[0])
	for _, pcr := range (*f.value)[1:] {
		fmt.Fprintf(&b, ",%d", pcr)
	}
	return b.String()
}

var algos = map[tpm2.Algorithm]string{
	tpm2.AlgUnknown: "",
	tpm2.AlgRSA:     "rsa",
	tpm2.AlgECC:     "ecc",
	tpm2.AlgSHA1:    "sha1",
	tpm2.AlgSHA256:  "sha256",
	tpm2.AlgSHA384:  "sha384",
	tpm2.AlgSHA512:  "sha512",
}

type algoFlag struct {
	value   *tpm2.Algorithm
	allowed []tpm2.Algorithm
}

func (f *algoFlag) Set(val string) error {
	present := false
	for _, algo := range f.allowed {
		if algos[algo] == val {
			*f.value = algo
			present = true
		}
	}
	if !present {
		return errors.New("unknown algorithm")
	}
	return nil
}

func (f *algoFlag) Type() string {
	return "algo"
}

func (f *algoFlag) String() string {
	return algos[*f.value]
}

// Allowed gives a string list of the permitted algorithm values for this flag.
func (f *algoFlag) Allowed() string {
	out := make([]string, len(f.allowed))
	for i, a := range f.allowed {
		out[i] = algos[a]
	}
	return strings.Join(out, ", ")
}

// Disable the "help" subcommand (and just use the -h/--help flags).
// This should be called on all commands with subcommands.
// See https://github.com/spf13/cobra/issues/587 for why this is needed.
func hideHelp(cmd *cobra.Command) {
	cmd.SetHelpCommand(&cobra.Command{Hidden: true})
}

// Lets this command specify an output file, for use with dataOutput().
func addOutputFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().String("output", "",
		"output file (defaults to stdout)")
}

// Lets this command specify an input file, for use with dataInput().
func addInputFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().String("input", "",
		"input file (defaults to stdin)")
}

// Lets this command specify an NVDATA index. Read it with
// cmd.Flags().GetUint32("index").
func addIndexFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().Uint32("index", 0,
		"NVDATA index, cannot be 0")
}

// Lets this command specify some number of PCR arguments, check if in range.
// Read them with getPCRs.
func addPCRsFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().Var(&pcrsFlag{new([]int)}, "pcrs", "comma separated list of PCR numbers")
}

// getPCRs returns the PCRs set with the flag from addPCRsFlag.
func getPCRs(cmd *cobra.Command) ([]int, error) {
	f := cmd.Flags().Lookup("pcrs")
	if f == nil {
		return nil, errors.New("flag pcrs is not defined")
	}
	v, ok := f.Value.(*pcrsFlag)
	if !ok {
		return nil, fmt.Errorf("flag pcrs has type %T, want *pcrsFlag", f.Value)
	}
	return *v.value, nil
}

// Lets this command specify the public key algorithm. Read it with
// getAlgo(cmd, "algo").
func addPublicKeyAlgoFlag(cmd *cobra.Command) {
	keyAlgo := tpm2.AlgRSA
	f := algoFlag{&keyAlgo, []tpm2.Algorithm{tpm2.AlgRSA, tpm2.AlgECC}}
	cmd.PersistentFlags().Var(&f, "algo", "public key algorithm: "+f.Allowed())
}

// Lets this command specify the hash algorithm. Read it with
// getAlgo(cmd, "hash-algo").
func addHashAlgoFlag(cmd *cobra.Command, defaultAlgo tpm2.Algorithm) {
	hashAlgo := defaultAlgo
	f := algoFlag{&hashAlgo, []tpm2.Algorithm{tpm2.AlgSHA1, tpm2.AlgSHA256, tpm2.AlgSHA384, tpm2.AlgSHA512}}
	cmd.PersistentFlags().Var(&f, "hash-algo", "hash algorithm: "+f.Allowed())
}

// getAlgo returns the algorithm set with a flag from addPublicKeyAlgoFlag or
// addHashAlgoFlag.
func getAlgo(cmd *cobra.Command, name string) (tpm2.Algorithm, error) {
	f := cmd.Flags().Lookup(name)
	if f == nil {
		return tpm2.AlgUnknown, fmt.Errorf("flag %s is not defined", name)
	}
	v, ok := f.Value.(*algoFlag)
	if !ok {
		return tpm2.AlgUnknown, fmt.Errorf("flag %s has type %T, want *algoFlag", name, f.Value)
	}
	return *v.value, nil
}

func addNonceFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().BytesHex("nonce", []byte{}, "hex encoded nonce for vTPM attestation, cannot be empty")
}

// Lets this command specify the type of output file (binary or txt)
func addFormatFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().String("format", "binarypb", "type of output file where attestation report stored <binarypb|textproto>")
}

func addTeeNonceflag(cmd *cobra.Command) {
	cmd.PersistentFlags().BytesHex("tee-nonce", []byte{}, "hex encoded teenonce for hardware attestation, can be empty")
}

func addTeeTechnology(cmd *cobra.Command) {
	cmd.PersistentFlags().String("tee-technology", "", "indicates the type of TEE hardware. Should be either empty or one of sev-snp or tdx")
}

// alwaysError implements io.ReadWriter by always returning an error
type alwaysError struct {
	error
}

func (ae alwaysError) Write([]byte) (int, error) {
	return 0, ae.error
}

func (ae alwaysError) Read(_ []byte) (n int, err error) {
	return 0, ae.error
}

// Handle to output data file. If there is an issue opening the file, the Writer
// returned will return the error upon any call to Write()
func dataOutput(cmd *cobra.Command) io.Writer {
	output, err := cmd.Flags().GetString("output")
	if err != nil {
		return alwaysError{err}
	}
	if output == "" {
		return cmd.OutOrStdout()
	}

	file, err := os.Create(output)
	if err != nil {
		return alwaysError{err}
	}
	return file
}

func openForWrite(path string) io.Writer {
	if path == "" {
		return os.Stdout
	}

	file, err := os.Create(path)
	if err != nil {
		return alwaysError{err}
	}
	return file
}

func writeProtoToOutput(message proto.Message, outFormat, outputPath string) error {
	var out []byte
	var err error
	switch outFormat {
	case "binarypb":
		out, err = proto.Marshal(message)
		if err != nil {
			return fmt.Errorf("failed to marshal proto: %v", message)
		}
	case "textproto":
		out = []byte(marshalOptions.Format(message))
	default:
		return fmt.Errorf("format should be either binarypb or textproto")
	}
	if _, err := openForWrite(outputPath).Write(out); err != nil {
		return fmt.Errorf("failed to write attestation report: %v", err)
	}
	return nil
}

// Handle to input data file. If there is an issue opening the file, the Reader
// returned will return the error upon any call to Read()
func dataInput(cmd *cobra.Command) io.Reader {
	input, err := cmd.Flags().GetString("input")
	if err != nil {
		return alwaysError{err}
	}
	if input == "" {
		return cmd.InOrStdin()
	}

	file, err := os.Open(input)
	if err != nil {
		return alwaysError{err}
	}
	return file
}

func readBytes(path string) ([]byte, error) {
	if path == "" {
		return nil, errors.New("must specify path to read file")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	bytes, err := io.ReadAll(file)
	if err != nil {
		return nil, fmt.Errorf("failed to read proto: %v", err)
	}
	return bytes, nil
}

// Reads binarypb file from path
func readProtoFromPath(path string, message proto.Message) error {
	requestBytes, err := readBytes(path)
	if err != nil {
		return fmt.Errorf("failed to read proto: %v", err)
	}

	err = proto.Unmarshal(requestBytes, message)
	if err != nil {
		return fmt.Errorf("failed to unmarshal proto: %v", err)
	}
	return nil
}

// Load SRK based on the given tpm2.Algorithm.
func getSRK(rwc io.ReadWriter, keyAlgo tpm2.Algorithm) (*client.Key, error) {
	switch keyAlgo {
	case tpm2.AlgRSA:
		return client.StorageRootKeyRSA(rwc)
	case tpm2.AlgECC:
		return client.StorageRootKeyECC(rwc)
	default:
		panic("unexpected keyAlgo")
	}
}

// Load EK based on the given tpm2.Algorithm.
func getEK(rwc io.ReadWriter, keyAlgo tpm2.Algorithm) (*client.Key, error) {
	switch keyAlgo {
	case tpm2.AlgRSA:
		return client.EndorsementKeyRSA(rwc)
	case tpm2.AlgECC:
		return client.EndorsementKeyECC(rwc)
	default:
		panic("unexpected keyAlgo")
	}
}
