// Package main implements the teeserver binary.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

var (
	challengeString string
)

func init() {
	evidenceCmd.Flags().StringVar(&challengeString, "challenge", "", "Challenge for the attestation evidence")
	rootCmd.AddCommand(evidenceCmd)
}

var evidenceCmd = &cobra.Command{
	Use:           "evidence",
	Short:         "Get VM attestation evidence from the TEE server",
	SilenceUsage:  true,
	SilenceErrors: true, // we handle printing the error ourselves
	RunE: func(_ *cobra.Command, args []string) error {
		if challengeString == "" {
			err := errors.New("--challenge is required")
			fmt.Fprintln(os.Stderr, "Error:", err)
			return err
		}

		client := http.Client{
			Transport: &http.Transport{
				DialContext: func(_ context.Context, _, _ string) (net.Conn, error) {
					return net.Dial("unix", socketPath)
				},
			},
		}

		var reqPayload struct {
			Challenge []byte `json:"challenge"`
		}
		reqPayload.Challenge = []byte(challengeString)

		jsonBody, err := json.Marshal(reqPayload)
		if err != nil {
			err = fmt.Errorf("failed to marshal request payload: %w", err)
			fmt.Fprintln(os.Stderr, "Error:", err)
			return err
		}

		// The evidenceEndpoint is /v1/evidence on the unix socket server
		resp, err := client.Post("http://localhost/v1/evidence", "application/json", bytes.NewBuffer(jsonBody))
		if err != nil {
			err = fmt.Errorf("failed to call TEE server: %w", err)
			fmt.Fprintln(os.Stderr, "Error:", err)
			return err
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			err = fmt.Errorf("failed to read response body: %w", err)
			fmt.Fprintln(os.Stderr, "Error:", err)
			return err
		}

		if resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("TEE server returned error status %d: %s", resp.StatusCode, string(body))
			fmt.Fprintln(os.Stderr, "Error:", err)
			return err
		}

		// Pretty-print the evidence JSON to stdout
		var prettyJSON bytes.Buffer
		if err := json.Indent(&prettyJSON, body, "", "  "); err != nil {
			fmt.Println(string(body)) // Fall back to raw string if not valid JSON
		} else {
			fmt.Println(prettyJSON.String())
		}

		return nil
	},
}
