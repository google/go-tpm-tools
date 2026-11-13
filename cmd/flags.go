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
func dataInput(path string) io.Reader {
	if path == "" {
		return os.Stdin
	}

	file, err := os.Open(path)
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

// Load SRK based on tpm2.Algorithm.
func getSRK(rwc io.ReadWriter, keyAlgo tpm2.Algorithm) (*client.Key, error) {
	switch keyAlgo {
	case tpm2.AlgRSA:
		return client.StorageRootKeyRSA(rwc)
	case tpm2.AlgECC:
		return client.StorageRootKeyECC(rwc)
	default:
		return nil, fmt.Errorf("unsupported SRK algorithm: %v", keyAlgo)
	}
}

// Load EK based on tpm2.Algorithm.
func getEK(rwc io.ReadWriter, keyAlgo tpm2.Algorithm) (*client.Key, error) {
	switch keyAlgo {
	case tpm2.AlgRSA:
		return client.EndorsementKeyRSA(rwc)
	case tpm2.AlgECC:
		return client.EndorsementKeyECC(rwc)
	default:
		return nil, fmt.Errorf("unsupported EK algorithm: %v", keyAlgo)
	}
}
