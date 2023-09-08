package cmd

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"

	"github.com/google/go-tpm-tools/cel"
	pb "github.com/google/go-tpm-tools/proto/attest"
	"github.com/spf13/cobra"
)

var eventlogCmd = &cobra.Command{
	Use:   "eventlog <pcr>",
	Short: "Parse binary event logs into a human-readable form",
	Long:  `Parse binary event logs, including the TCG firmware event log and canonical event log, into a human-readable form`,
	Args:  cobra.NoArgs,
}

var celCmd = &cobra.Command{
	Use:   "cel",
	Short: "Parse the given canonical event log. This command is currently unstable",
	RunE: func(cmd *cobra.Command, args []string) error {
		celBytes, err := io.ReadAll(dataInput())
		if err != nil {
			return fmt.Errorf("failed to parse canonical event log: %v", err)
		}

		eventLog, err := cel.DecodeToCEL(bytes.NewBuffer(celBytes))
		if err != nil {
			return fmt.Errorf("failed to decode input file as canonical event log: %v", err)
		}

		if len(eventLog.Records) == 0 {
			fmt.Fprintln(debugOutput(), "received empty canonical event log")
			return nil
		}

		celJSON, err := json.MarshalIndent(eventLog, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal canonical event log as JSON: %v", err)
		}
		fmt.Fprintln(dataOutput(), string(celJSON))

		// Use presence of first Record to detect whether the CEL is from COS.
		seenSeparator := false
		if eventLog.Records[0].Content.IsCosTlv() {
			fmt.Fprintln(debugOutput(), "detected COS TLV in the canonical event log")
			cosState := &pb.AttestedCosState{}
			cosState.Container = &pb.ContainerState{}
			cosState.Container.Args = make([]string, 0)
			cosState.Container.EnvVars = make(map[string]string)
			cosState.Container.OverriddenEnvVars = make(map[string]string)

			for i, record := range eventLog.Records {
				cosTLV, err := record.Content.ParseToCosTlv()
				if err != nil {
					return fmt.Errorf("failed to parse record %d TLV as COS TLV", i)
				}
				if seenSeparator {
					return fmt.Errorf("found bad COS event log: record of type %v found after LaunchSeparator event", cosTLV.EventType)
				}
				seenSeparator, err = cel.UpdateCosState(cosState, cosTLV)
				if err != nil {
					return fmt.Errorf("failed to update AttestedCosState from CEL: %v", err)
				}
			}
			fmt.Fprintln(debugOutput(), "for debug use only: implied AttestedCosState from the input CEL")
			output, err := marshalOptions.Marshal(cosState)
			if err != nil {
				return fmt.Errorf("failed to marshal AttestedCosState from CEL as textproto: %v", err)
			}
			if _, err := debugOutput().Write(output); err != nil {
				return fmt.Errorf("failed to write AttestedCosState: %v", err)
			}
		}
		return nil
	},
}

func init() {
	RootCmd.AddCommand(eventlogCmd)
	eventlogCmd.AddCommand(celCmd)
	addInputFlag(celCmd)
	addOutputFlag(celCmd)
}
