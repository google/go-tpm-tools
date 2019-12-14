package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
	"github.com/spf13/cobra"
)

var (
	output   string
	input    string
	nvIndex  uint32
	keyAlgo  string
	pcrs     []uint
	hashAlgo string
)

// Disable the "help" subcommand (and just use the -h/--help flags).
// This should be called on all commands with subcommands.
// See https://github.com/spf13/cobra/issues/587 for why this is needed.
func hideHelp(cmd *cobra.Command) {
	cmd.SetHelpCommand(&cobra.Command{Hidden: true})
}

// Lets this command specify an output file, for use with dataOutput().
func addOutputFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&output, "output", "",
		"output file (defaults to stdout)")
}

// Lets this command specify an input file, for use with dataInput().
func addInputFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&input, "input", "",
		"input file (defaults to stdin)")
}

// Lets this command specify an NVDATA index, for use with nvIndex.
func addIndexFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().Uint32Var(&nvIndex, "index", 0,
		"NVDATA index, cannot be 0")
}

// Lets this command specify some number of PCR arguments, check if in range.
func addPCRsFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().UintSliceVar(&pcrs, "pcrs", nil,
		"comma separated list of PCR numbers")
}

// Lets this command specify the public key algorithm.
func addPublicKeyAlgoFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&keyAlgo, "algo", "rsa",
		"public key algorithm, \"rsa\" or \"ecc\"")
}

func addHashAlgoFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&hashAlgo, "hash-algo", "sha256",
		"hash algorithm, \"sha1\",  \"sha256\", or \"sha384\"")
}

// alwaysError implements io.ReadWriter by always returning an error
type alwaysError struct {
	error
}

func (ae alwaysError) Write([]byte) (int, error) {
	return 0, ae.error
}

func (ae alwaysError) Read(p []byte) (n int, err error) {
	return 0, ae.error
}

// Handle to output data file. If there is an issue opening the file, the Writer
// returned will return the error upon any call to Write()
func dataOutput() io.Writer {
	if output == "" {
		return os.Stdout
	}

	file, err := os.Create(output)
	if err != nil {
		return alwaysError{err}
	}
	return file
}

// Handle to input data file. If there is an issue opening the file, the Reader
// returned will return the error upon any call to Read()
func dataInput() io.Reader {
	if input == "" {
		return os.Stdin
	}

	file, err := os.Open(input)
	if err != nil {
		return alwaysError{err}
	}
	return file
}

// Get the algorithm for public key.
func getAlgo() (tpm2.Algorithm, error) {
	switch keyAlgo {
	case "rsa":
		return tpm2.AlgRSA, nil
	case "ecc":
		return tpm2.AlgECC, nil
	default:
		return tpm2.AlgNull, fmt.Errorf("invalid argument %q for \"--algo\" flag", keyAlgo)
	}
}

func getHashAlgo() (tpm2.Algorithm, error) {
	switch hashAlgo {
	case "sha1":
		return tpm2.AlgSHA1, nil
	case "sha256":
		return tpm2.AlgSHA256, nil
	case "sha384":
		return tpm2.AlgSHA384, nil
	case "sha512":
		return tpm2.AlgSHA512, nil
	default:
		return tpm2.AlgNull, fmt.Errorf("invalid argument %q for \"--hash-algo\" flag", hashAlgo)
	}
}

func getSelection() (tpm2.PCRSelection, error) {
	hash, err := getHashAlgo()
	sel := tpm2.PCRSelection{Hash: hash}
	for _, val := range pcrs {
		sel.PCRs = append(sel.PCRs, int(val))
	}
	return sel, err
}

func getSRKwithAlgo(rwc io.ReadWriter, algo tpm2.Algorithm) (*tpm2tools.Key, error) {
	switch algo {
	case tpm2.AlgRSA:
		return tpm2tools.StorageRootKeyRSA(rwc)
	case tpm2.AlgECC:
		return tpm2tools.StorageRootKeyECC(rwc)
	default:
		return nil, fmt.Errorf("cannot create SRK for the given algorithm: 0x%x", algo)
	}
}

func getEKwithAlgo(rwc io.ReadWriter, algo tpm2.Algorithm) (*tpm2tools.Key, error) {
	switch algo {
	case tpm2.AlgRSA:
		return tpm2tools.EndorsementKeyRSA(rwc)
	case tpm2.AlgECC:
		return tpm2tools.EndorsementKeyECC(rwc)
	default:
		return nil, fmt.Errorf("cannot create EK for the given algorithm: 0x%x", algo)
	}
}

// Load SRK based on tpm2.Algorithm set in the global flag vars.
func getSRK(rwc io.ReadWriter) (*tpm2tools.Key, error) {
	algo, err := getAlgo()
	if err != nil {
		return nil, err
	}
	return getSRKwithAlgo(rwc, algo)
}

// Load EK based on tpm2.Algorithm set in the global flag vars.
func getEK(rwc io.ReadWriter) (*tpm2tools.Key, error) {
	algo, err := getAlgo()
	if err != nil {
		return nil, err
	}
	return getEKwithAlgo(rwc, algo)
}
