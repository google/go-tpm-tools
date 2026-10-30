// Package cmd contains a CLI to interact with TPM.
package cmd

import (
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/spf13/cobra"
	"google.golang.org/protobuf/encoding/prototext"
)

type gotpmOptions struct {
	tpmOpener func(tpmPath string) (io.ReadWriteCloser, error)

	quiet   bool
	verbose bool
	tpmPath string
}

// NewGotpmCmd returns the entrypoint for gotpm.
func NewGotpmCmd() *cobra.Command {
	return newGotpmCmd(openImpl, nil)
}

func newGotpmCmd(tpmOpener func(tpmPath string) (io.ReadWriteCloser, error), httpClient *http.Client) *cobra.Command {
	o := &gotpmOptions{tpmOpener: tpmOpener}
	root := &cobra.Command{
		Use: "gotpm",
		Long: `Command line tool for the go-tpm TSS

This tool allows performing TPM2 operations from the command line.
See the per-command documentation for more information.`,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			if o.quiet && o.verbose {
				return fmt.Errorf("cannot specify both --quiet and --verbose")
			}
			cmd.SilenceUsage = true
			return nil
		},
	}
	root.PersistentFlags().BoolVar(&o.quiet, "quiet", false,
		"print nothing if command is successful")
	root.PersistentFlags().BoolVar(&o.verbose, "verbose", false,
		"print additional info to stdout")
	addTPMPathFlag(root, &o.tpmPath)
	hideHelp(root)
	root.AddCommand(
		newAttestCmd(o),
		newFlushCmd(o),
		newPubkeyCmd(o),
		newReadCmd(o),
		newRegisterCmd(o),
		newSealCmd(o),
		newUnsealCmd(o),
		newTokenCmd(o, httpClient),
		newVerifyCmd(),
	)
	return root
}

func (o *gotpmOptions) messageOutput() io.Writer {
	if o.quiet {
		return io.Discard
	}
	return os.Stdout
}

func (o *gotpmOptions) debugOutput() io.Writer {
	if o.verbose {
		return os.Stdout
	}
	return io.Discard
}

// Default Text Marshalling options
var marshalOptions = prototext.MarshalOptions{
	Multiline: true,
	EmitASCII: true,
}
var unmarshalOptions = prototext.UnmarshalOptions{}
