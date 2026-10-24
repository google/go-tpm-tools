// Package cmd contains a CLI to interact with TPM.
package cmd

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/prototext"
)

// NewRootCmd returns the gotpm command tree. Each call returns new commands
// with their own flag values.
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
			quiet, err := cmd.Flags().GetBool("quiet")
			if err != nil {
				return err
			}
			verbose, err := cmd.Flags().GetBool("verbose")
			if err != nil {
				return err
			}
			if quiet && verbose {
				return fmt.Errorf("cannot specify both --quiet and --verbose")
			}
			cmd.SilenceUsage = true
			return nil
		},
	}
	root.PersistentFlags().Bool("quiet", false,
		"print nothing if command is successful")
	root.PersistentFlags().Bool("verbose", false,
		"print additional info to stdout")
	addTPMPathFlag(root)
	hideHelp(root)
	root.AddCommand(
		newAttestCmd(e),
		newFlushCmd(e),
		newPubkeyCmd(e),
		newReadCmd(e),
		newRegisterCmd(),
		newSealCmd(e),
		newUnsealCmd(e),
		newTokenCmd(e),
		newVerifyCmd(),
	)
	return root
}

// messageOutput returns the writer for normal messages of cmd.
func messageOutput(cmd *cobra.Command) io.Writer {
	if quiet, err := cmd.Flags().GetBool("quiet"); err == nil && quiet {
		return io.Discard
	}
	return cmd.OutOrStdout()
}

// debugOutput returns the writer for debug messages of cmd.
func debugOutput(cmd *cobra.Command) io.Writer {
	if verbose, err := cmd.Flags().GetBool("verbose"); err == nil && verbose {
		return cmd.OutOrStdout()
	}
	return io.Discard
}

// Default Text Marshalling options
var marshalOptions = prototext.MarshalOptions{
	Multiline: true,
	EmitASCII: true,
}
var unmarshalOptions = prototext.UnmarshalOptions{}
