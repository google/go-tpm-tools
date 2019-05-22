package cmd

import (
	"io"
	"os"

	"github.com/spf13/cobra"
)

var (
	output  string
	input   string
	nvIndex uint32
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
		"output file for TPM data (defaults to stdout)")
}

// Lets this command specify an input file, for use with dataInput().
func addInputFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&input, "input", "",
		"input file for TPM data (defaults to stdin)")
}

// Lets this command specify an NVDATA index, for use with nvIndex.
func addIndexFlag(cmd *cobra.Command) {
	cmd.PersistentFlags().Uint32Var(&nvIndex, "index", 0,
		"NVDATA index, cannot be 0")
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
