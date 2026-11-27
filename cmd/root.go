// Package cmd contains a CLI to interact with TPM.
package cmd

import (
	"context"
	"errors"
	"io"
	"net/http"

	"github.com/spf13/cobra"
	"golang.org/x/oauth2/google"
	"google.golang.org/protobuf/encoding/prototext"
)

var errQuietAndVerbose = errors.New("cannot specify both --quiet and --verbose")

type outputMode int

const (
	outputNormal outputMode = iota
	outputQuiet
	outputVerbose
)

type rootFlags struct {
	quiet   bool
	verbose bool
	tpmPath string
}

type rootOptions struct {
	output  outputMode
	tpmPath string
}

func addRootFlags(cmd *cobra.Command, f *rootFlags) {
	cmd.PersistentFlags().BoolVar(&f.quiet, "quiet", false,
		"print nothing if command is successful")
	cmd.PersistentFlags().BoolVar(&f.verbose, "verbose", false,
		"print additional info to stdout")
	addTPMPathFlag(cmd, &f.tpmPath)
}

func (f rootFlags) parse() (rootOptions, error) {
	if f.quiet && f.verbose {
		return rootOptions{}, errQuietAndVerbose
	}
	mode := outputNormal
	if f.quiet {
		mode = outputQuiet
	} else if f.verbose {
		mode = outputVerbose
	}
	return rootOptions{
		output:  mode,
		tpmPath: f.tpmPath,
	}, nil
}

type gotpmOptions struct {
	tpmOpener  func(tpmPath string) (io.ReadWriteCloser, error)
	httpClient func(context.Context) (*http.Client, error)
	out        func() io.Writer
	root       rootOptions
}

// NewGotpmCmd returns the entrypoint for gotpm.
func NewGotpmCmd() *cobra.Command {
	return newGotpmCmd(openImpl, func(ctx context.Context) (*http.Client, error) {
		return google.DefaultClient(ctx)
	})
}

func newGotpmCmd(tpmOpener func(tpmPath string) (io.ReadWriteCloser, error), httpClient func(context.Context) (*http.Client, error)) *cobra.Command {
	var flags rootFlags
	o := &gotpmOptions{
		tpmOpener:  tpmOpener,
		httpClient: httpClient,
	}
	root := &cobra.Command{
		Use: "gotpm",
		Long: `Command line tool for the go-tpm TSS

This tool allows performing TPM2 operations from the command line.
See the per-command documentation for more information.`,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			opts, err := flags.parse()
			if err != nil {
				return err
			}
			o.root = opts
			cmd.SilenceUsage = true
			return nil
		},
	}
	o.out = root.OutOrStdout
	addRootFlags(root, &flags)
	hideHelp(root)
	root.AddCommand(
		newAttestCmd(o),
		newFlushCmd(o),
		newPubkeyCmd(o),
		newReadCmd(o),
		newRegisterCmd(o),
		newSealCmd(o),
		newUnsealCmd(o),
		newTokenCmd(o),
		newVerifyCmd(),
	)
	return root
}

func (o *gotpmOptions) messageOutput() io.Writer {
	if o.root.output == outputQuiet {
		return io.Discard
	}
	return o.out()
}

func (o *gotpmOptions) debugOutput() io.Writer {
	if o.root.output == outputVerbose {
		return o.out()
	}
	return io.Discard
}

// Default Text Marshalling options
var marshalOptions = prototext.MarshalOptions{
	Multiline: true,
	EmitASCII: true,
}
var unmarshalOptions = prototext.UnmarshalOptions{}
