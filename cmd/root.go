// Package cmd contains a CLI to interact with TPM.
package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/prototext"
)

// NewRootCmd returns the entrypoint for gotpm.
func NewRootCmd() *cobra.Command {
	return newRootCmd()
}

func newRootCmd(opts ...envOption) *cobra.Command {
	e := &env{}
	for _, opt := range opts {
		opt(e)
	}

	root := &cobra.Command{
		Use: "gotpm",
		Long: `Command line tool for the go-tpm TSS

This tool allows performing TPM2 operations from the command line.
See the per-command documentation for more information.`,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if quiet && verbose {
				return fmt.Errorf("cannot specify both --quiet and --verbose")
			}
			cmd.SilenceUsage = true
			return nil
		},
	}
	root.PersistentFlags().BoolVar(&quiet, "quiet", false,
		"print nothing if command is successful")
	root.PersistentFlags().BoolVar(&verbose, "verbose", false,
		"print additional info to stdout")
	addTPMPathFlag(root)
	hideHelp(root)
	root.AddCommand(
		attestCmd,
		newFlushCmd(e),
		pubkeyCmd,
		readCmd,
		registerCmd,
		sealCmd,
		unsealCmd,
		tokenCmd,
		verifyCmd,
	)
	return root
}

var (
	quiet   bool
	verbose bool
)

func messageOutput() io.Writer {
	if quiet {
		return io.Discard
	}
	return os.Stdout
}

func debugOutput() io.Writer {
	if verbose {
		return os.Stdout
	}
	return io.Discard
}

func (e *env) messageOutput() io.Writer {
	return messageOutput()
}

func (e *env) debugOutput() io.Writer {
	return debugOutput()
}

// Default Text Marshalling options
var marshalOptions = prototext.MarshalOptions{
	Multiline: true,
	EmitASCII: true,
}
var unmarshalOptions = prototext.UnmarshalOptions{}
