package cmd

import (
	"fmt"

	"github.com/google/go-tpm-tools/tpm2tools"
	"github.com/google/go-tpm/tpm2"
	"github.com/spf13/cobra"
)

var handleNames = map[string][]tpm2.HandleType{
	"all":       []tpm2.HandleType{tpm2.HandleTypeLoadedSession, tpm2.HandleTypeSavedSession, tpm2.HandleTypeTransient},
	"loaded":    []tpm2.HandleType{tpm2.HandleTypeLoadedSession},
	"saved":     []tpm2.HandleType{tpm2.HandleTypeSavedSession},
	"transient": []tpm2.HandleType{tpm2.HandleTypeTransient},
}

var flushCmd = &cobra.Command{
	Use:   "flush <all | loaded | saved | transient>",
	Short: "Close active handles on the TPM",
	Long: `Close some or all currently active handles on the TPM

Most TPM operations require an active handle, representing some object within
the TPM. However, most TPMs also limit the number of simultaneous active handles
(usually a max of 3). This command allows for "leaked" handles (handles that
have not been properly closed) to be flushed, freeing up handles for use with
future TPM operations.

Which handles are flushed depends on the argument passed:
	loaded    - only flush the loaded session handles
	saved     - only flush the saved session handles
	transient - only flush the transient handles
	all       - flush all loaded, saved, and transient handles`,
	ValidArgs: func() []string {
		// The keys from the handleNames map are our valid arguments
		keys := make([]string, len(handleNames))
		for k := range handleNames {
			keys = append(keys, k)
		}
		return keys
	}(),
	Args: cobra.ExactValidArgs(1),
	RunE: func(cmd *cobra.Command, args []string) error {
		cmd.SilenceUsage = true
		rwc, err := openTpm()
		if err != nil {
			return err
		}
		defer rwc.Close()

		totalHandles := 0
		for _, handleType := range handleNames[args[0]] {
			handles, err := tpm2tools.Handles(rwc, handleType)
			if err != nil {
				return fmt.Errorf("getting handles: %v", err)
			}
			for _, handle := range handles {
				if err = tpm2.FlushContext(rwc, handle); err != nil {
					return fmt.Errorf("flushing handle 0x%x: %v", handle, err)
				}

				fmt.Fprintf(debugOutput(), "Handle 0x%x flushed\n", handle)
				totalHandles++
			}
		}

		fmt.Fprintf(messageOutput(), "%d handles flushed\n", totalHandles)
		return nil
	},
}

func init() {
	RootCmd.AddCommand(flushCmd)
}
